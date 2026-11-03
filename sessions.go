package edge

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// earlyExpiry: a cached token is dropped this long before it or its session ends (P11.1).
const earlyExpiry = 30 * time.Second

// endedPage is how many ended sessions one pull asks for.
const endedPage = 500

type entry struct {
	token string
	until time.Time // min(expires_at, session_until) - earlyExpiry
}

// flight is one exchange in progress; the others for the same session wait for it.
type flight struct {
	done chan struct{}
	tok  string
	err  error
}

// sessions is the token cache of one edge instance: per session digest, the token the identity member gave, until
// shortly before it or the session ends; at most one exchange in flight per session (P11.1). It lives in a package
// variable (P11.10), so Traefik's configuration reloads, which build the middleware again, keep it.
type sessions struct {
	id  identity
	now func() time.Time

	mu      sync.Mutex
	cache   map[string]entry
	flights map[string]*flight
	cursor  *cursor
}

func newSessions(id identity) *sessions {
	return &sessions{id: id, now: time.Now, cache: map[string]entry{}, flights: map[string]*flight{}}
}

// token returns a usable token for the session: the cached one, or a new exchange (renew false for a polling
// request's, P11.7). errSessionEnded when the session is over; another error when the identity member cannot answer.
func (s *sessions) token(ctx context.Context, digest string, renew bool) (string, error) {
	s.mu.Lock()
	if e, ok := s.cache[digest]; ok && s.now().Before(e.until) {
		s.mu.Unlock()
		return e.token, nil
	}
	s.mu.Unlock()
	return s.exchange(ctx, digest, renew)
}

// exchange asks the identity member for a new token; a request that finds an exchange of the same session in
// flight waits for its result.
func (s *sessions) exchange(ctx context.Context, digest string, renew bool) (string, error) {
	s.mu.Lock()
	if f, ok := s.flights[digest]; ok {
		s.mu.Unlock()
		select {
		case <-f.done:
			return f.tok, f.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	s.flights[digest] = f
	s.mu.Unlock()

	r, err := s.id.Exchange(context.WithoutCancel(ctx), digest, renew)
	s.mu.Lock()
	delete(s.flights, digest)
	switch {
	case err == nil:
		until := time.UnixMilli(r.ExpiresAtMs)
		if su := time.UnixMilli(r.SessionUntilMs); r.SessionUntilMs > 0 && su.Before(until) {
			until = su
		}
		s.cache[digest] = entry{token: r.AccessToken, until: until.Add(-earlyExpiry)}
		f.tok = r.AccessToken
	case err == errSessionEnded:
		delete(s.cache, digest)
	}
	f.err = err
	s.mu.Unlock()
	close(f.done)
	return f.tok, f.err
}

// drop forgets a session's token (TOKEN_STALE, logout, an ended session).
func (s *sessions) drop(digest string) {
	s.mu.Lock()
	delete(s.cache, digest)
	s.mu.Unlock()
}

// pull reads the sessions that ended since the last pull and drops their tokens; a reset clears the whole cache
// (P11.5). A failure keeps the cache: the ends are all made in the identity member, so while it cannot be reached
// the tokens end at their expiry at the latest (D61).
func (s *sessions) pull(ctx context.Context) error {
	s.mu.Lock()
	after := s.cursor
	s.mu.Unlock()
	for {
		r, err := s.id.Ended(ctx, after, endedPage)
		if err != nil {
			return err
		}
		s.mu.Lock()
		if r.Reset {
			s.cache = map[string]entry{}
		}
		for _, d := range r.SessionDigests {
			delete(s.cache, d)
		}
		if r.Next != nil {
			s.cursor = r.Next
		}
		after = s.cursor
		s.mu.Unlock()
		if r.Reset || len(r.SessionDigests) < endedPage {
			return nil
		}
	}
}

// poll pulls every interval until ctx ends. A panic here is not caught by the edge's recovery middleware and would
// end the whole Traefik process: it is recovered, logged, and the loop goes on.
func (s *sessions) poll(ctx context.Context, every time.Duration) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("be-edge: the ended-session poller panicked and starts again: %v", p)
			go s.poll(ctx, every)
		}
	}()
	t := time.NewTicker(every)
	defer t.Stop()
	failing := false
	for {
		if err := s.pull(ctx); err != nil {
			if !failing {
				log.Printf("be-edge: the identity member's ended sessions cannot be read: %v", err)
			}
			failing = true
		} else if failing {
			fmt.Fprintln(os.Stdout, "be-edge: the identity member's ended sessions are read again")
			failing = false
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
