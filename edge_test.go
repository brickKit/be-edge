package edge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIdentity answers like SessionService: a token per exchange (numbered), ended pages from a script.
type fakeIdentity struct {
	mu        sync.Mutex
	exchanges int
	renews    []bool
	refuse    error         // the next exchanges' answer when set
	hold      chan struct{} // exchanges wait for it when set
	pages     []endedResponse
	pulls     []*cursor
	pullErr   error
}

func (f *fakeIdentity) Exchange(_ context.Context, d string, renew bool) (exchangeResponse, error) {
	f.mu.Lock()
	f.exchanges++
	n := f.exchanges
	f.renews = append(f.renews, renew)
	refuse, hold := f.refuse, f.hold
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if refuse != nil {
		return exchangeResponse{}, refuse
	}
	now := time.Now()
	return exchangeResponse{AccessToken: "tok-" + d[:8] + "-" + string(rune('0'+n)), Principal: "p",
		ExpiresAtMs: now.Add(5 * time.Minute).UnixMilli(), SessionUntilMs: now.Add(time.Hour).UnixMilli()}, nil
}

func (f *fakeIdentity) Ended(_ context.Context, after *cursor, _ uint32) (endedResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pulls = append(f.pulls, after)
	if f.pullErr != nil {
		return endedResponse{}, f.pullErr
	}
	if len(f.pages) == 0 {
		return endedResponse{Next: after}, nil
	}
	p := f.pages[0]
	f.pages = f.pages[1:]
	return p, nil
}

func (f *fakeIdentity) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.exchanges }

// component records what it got and answers from a script (status codes, or "TOKEN_STALE").
type component struct {
	mu      sync.Mutex
	answers []string
	got     []http.Request
	bodies  []string
}

func (c *component) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.got = append(c.got, *r)
	c.bodies = append(c.bodies, string(b))
	a := "200"
	if len(c.answers) > 0 {
		a, c.answers = c.answers[0], c.answers[1:]
	}
	c.mu.Unlock()
	switch a {
	case "TOKEN_STALE", "TOKEN_INVALID":
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"status":401,"reason":"` + a + `","domain":"be"}`))
	default:
		code := 0
		for _, ch := range a {
			code = code*10 + int(ch-'0')
		}
		w.Header().Set("X-Component", "yes")
		w.WriteHeader(code)
		_, _ = w.Write([]byte("answer " + a))
	}
}

func (c *component) calls() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.got) }

func setup(t *testing.T) (*fakeIdentity, *component, *handler) {
	t.Helper()
	id := &fakeIdentity{}
	c := &component{}
	features := filepath.Join(t.TempDir(), "features.json")
	if err := os.WriteFile(features, []byte(`{"components":["erp/sales"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := CreateConfig()
	cfg.FeaturesFile = features
	cfg.ReplayLimit = 16
	return id, c, newHandler(c, cfg, newSessions(id))
}

func request(method, path, body, cookie string, headers ...string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: DefaultCookie, Value: cookie})
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func reasonOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct{ Reason string }
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	return p.Reason
}

// P11.1: the session's token goes in, a browser's own Authorization never; one exchange, then the cache.
func TestTheSessionsTokenIsInjectedAndCached(t *testing.T) {
	id, c, h := setup(t)
	for i := 0; i < 3; i++ {
		w := serve(h, request("GET", "/api/x", "", "cookie-a", "Authorization", "Bearer forged"))
		if w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
	}
	if id.count() != 1 {
		t.Errorf("%d exchanges, want 1 (then the cache)", id.count())
	}
	want := "Bearer tok-" + digest("cookie-a")[:8] + "-1"
	for i, r := range c.got {
		if got := r.Header.Get("Authorization"); got != want {
			t.Errorf("request %d carried %q, want %q", i, got, want)
		}
	}
	w := serve(h, request("GET", "/api/public", "", "", "Authorization", "Bearer forged"))
	if w.Code != 200 || c.got[3].Header.Get("Authorization") != "" {
		t.Errorf("without a session: forwarded with no Authorization at all, got %q", c.got[3].Header.Get("Authorization"))
	}
}

// P11.1: a token is dropped before it ends.
func TestATokenIsNotUsedInItsLastSeconds(t *testing.T) {
	id, _, h := setup(t)
	now := time.Now()
	h.sessions.now = func() time.Time { return now }
	serve(h, request("GET", "/api/x", "", "cookie-a"))
	h.sessions.now = func() time.Time { return now.Add(5*time.Minute - 29*time.Second) }
	serve(h, request("GET", "/api/x", "", "cookie-a"))
	if id.count() != 2 {
		t.Errorf("%d exchanges: 29 seconds before the end the token is not used any more", id.count())
	}
}

// P11.1: requests of one session arriving together while there is no token make one exchange.
func TestConcurrentMissesExchangeOnce(t *testing.T) {
	id, c, h := setup(t)
	id.hold = make(chan struct{})
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if serve(h, request("GET", "/api/x", "", "cookie-a")).Code == 200 {
				ok.Add(1)
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for id.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // the others reach the flight
	close(id.hold)
	wg.Wait()
	if id.count() != 1 || ok.Load() != 10 || c.calls() != 10 {
		t.Errorf("exchanges %d (want 1), answered %d, forwarded %d", id.count(), ok.Load(), c.calls())
	}
}

// P11.2: a state-changing request with the session cookie needs BE-Request; one without the cookie does not.
func TestStateChangingRequestsNeedTheHeader(t *testing.T) {
	id, c, h := setup(t)
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		w := serve(h, request(m, "/api/x", "{}", "cookie-a"))
		if w.Code != 403 || reasonOf(t, w) != "CSRF_HEADER_REQUIRED" {
			t.Errorf("%s without the header: %d %s", m, w.Code, reasonOf(t, w))
		}
	}
	if c.calls() != 0 || id.count() != 0 {
		t.Errorf("refused requests reached the component (%d) or the identity member (%d)", c.calls(), id.count())
	}
	if w := serve(h, request("POST", "/api/x", "{}", "cookie-a", "BE-Request", "1")); w.Code != 200 {
		t.Errorf("with the header: %d", w.Code)
	}
	if w := serve(h, request("POST", "/callback", "{}", "")); w.Code != 200 {
		t.Errorf("an external callback without the cookie: %d", w.Code)
	}
}

// P11.3: TOKEN_STALE: a new token, the same request (and body) once; the second answer as it is.
func TestTokenStaleIsReplayedOnce(t *testing.T) {
	id, c, h := setup(t)
	c.answers = []string{"TOKEN_STALE", "201"}
	w := serve(h, request("POST", "/api/x", `{"a":1}`, "cookie-a", "BE-Request", "1"))
	if w.Code != 201 || w.Body.String() != "answer 201" || w.Header().Get("X-Component") != "yes" {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	if c.calls() != 2 || id.count() != 2 || c.bodies[1] != `{"a":1}` {
		t.Errorf("calls %d, exchanges %d, replayed body %q", c.calls(), id.count(), c.bodies[1])
	}
	if got, want := c.got[1].Header.Get("Authorization"), "Bearer tok-"+digest("cookie-a")[:8]+"-2"; got != want {
		t.Errorf("the replay carried %q, want the second exchange's token %q", got, want)
	}
	// a second TOKEN_STALE: log in again
	c.answers = []string{"TOKEN_STALE", "TOKEN_STALE"}
	if w := serve(h, request("GET", "/api/x", "", "cookie-a")); w.Code != 401 || reasonOf(t, w) != "SESSION_ENDED" {
		t.Errorf("stale twice: %d %s", w.Code, reasonOf(t, w))
	}
	// another 401 passes through, not replayed
	n := c.calls()
	c.answers = []string{"TOKEN_INVALID"}
	if w := serve(h, request("GET", "/api/x", "", "cookie-a")); w.Code != 401 || reasonOf(t, w) != "TOKEN_INVALID" || c.calls() != n+1 {
		t.Errorf("TOKEN_INVALID: %d %s, calls %d", w.Code, reasonOf(t, w), c.calls()-n)
	}
	// 5xx is never retried
	c.answers = []string{"500"}
	if w := serve(h, request("POST", "/api/x", "{}", "cookie-a", "BE-Request", "1")); w.Code != 500 || c.calls() != n+2 {
		t.Errorf("500: %d, calls %d", w.Code, c.calls()-n)
	}
}

// P11.3: a body over B_replay is streamed through, and a TOKEN_STALE answer to it is not replayed.
func TestABodyOverTheLimitIsNotReplayed(t *testing.T) {
	_, c, h := setup(t)
	big := strings.Repeat("x", 17)
	c.answers = []string{"TOKEN_STALE"}
	w := serve(h, request("POST", "/api/x", big, "cookie-a", "BE-Request", "1"))
	if w.Code != 503 || reasonOf(t, w) != "AUTHORIZATION_UNPROVABLE" || c.calls() != 1 || c.bodies[0] != big {
		t.Errorf("got %d %s, calls %d, body %q", w.Code, reasonOf(t, w), c.calls(), c.bodies[0])
	}
	c.answers = []string{"TOKEN_STALE", "201"}
	if w := serve(h, request("POST", "/api/x", big[:16], "cookie-a", "BE-Request", "1")); w.Code != 201 {
		t.Errorf("at the limit: replayed, got %d", w.Code)
	}
}

// P11.4: a session that ended answers SESSION_ENDED; an identity member that cannot answer, 503.
func TestAFailedExchange(t *testing.T) {
	id, c, h := setup(t)
	id.refuse = errSessionEnded
	if w := serve(h, request("GET", "/api/x", "", "cookie-a")); w.Code != 401 || reasonOf(t, w) != "SESSION_ENDED" {
		t.Errorf("ended: %d %s", w.Code, reasonOf(t, w))
	}
	id.refuse = errors.New("connection refused")
	w := serve(h, request("GET", "/api/x", "", "cookie-a"))
	if w.Code != 503 || reasonOf(t, w) != "DEPENDENCY_UNAVAILABLE" || !strings.Contains(w.Body.String(), `"dependency":"iam"`) {
		t.Errorf("unavailable: %d %s", w.Code, w.Body.String())
	}
	if c.calls() != 0 {
		t.Error("nothing reached the component")
	}
}

// P11.5, P11.6: ended sessions and a logout drop the cached token; a reset clears all; a failed pull keeps them.
func TestEndedSessionsAndLogoutDropTheirTokens(t *testing.T) {
	id, _, h := setup(t)
	for _, ck := range []string{"a", "b", "c"} {
		serve(h, request("GET", "/api/x", "", ck))
	}
	id.pages = []endedResponse{{SessionDigests: []string{digest("a")}, Next: &cursor{Impl: "i", Epoch: "1.1", Seq: 7}}}
	if err := h.sessions.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	serve(h, request("GET", "/api/x", "", "a"))
	serve(h, request("GET", "/api/x", "", "b"))
	if id.count() != 4 {
		t.Errorf("%d exchanges: only the ended session exchanges again", id.count())
	}
	id.pullErr = errors.New("unreachable")
	if err := h.sessions.pull(context.Background()); err == nil {
		t.Fatal("the failure is reported")
	}
	id.pullErr = nil
	if err := h.sessions.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := id.pulls[len(id.pulls)-1]; c == nil || c.Seq != 7 {
		t.Errorf("the next pull continues from the cursor, got %+v", c)
	}
	serve(h, request("POST", DefaultLogoutPath, "", "b", "BE-Request", "1"))
	serve(h, request("GET", "/api/x", "", "b"))
	if id.count() != 5 {
		t.Errorf("%d exchanges: after the logout b exchanges again", id.count())
	}
	id.pages = []endedResponse{{Reset: true, Next: &cursor{Impl: "j", Epoch: "2.1"}}}
	if err := h.sessions.pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	serve(h, request("GET", "/api/x", "", "c"))
	if id.count() != 6 {
		t.Errorf("%d exchanges: a reset clears the cache", id.count())
	}
}

// P11.7: a polling request's exchange does not renew the session's idle time.
func TestAPollingRequestDoesNotRenew(t *testing.T) {
	id, _, h := setup(t)
	serve(h, request("GET", "/api/x", "", "a", "BE-Polling", "1"))
	serve(h, request("GET", "/api/x", "", "b"))
	if len(id.renews) != 2 || id.renews[0] || !id.renews[1] {
		t.Errorf("renew_idle %v, want [false true]", id.renews)
	}
}

// P11.8: features for a live session only.
func TestFeaturesForLiveSessionsOnly(t *testing.T) {
	id, c, h := setup(t)
	if w := serve(h, request("GET", DefaultFeaturesPath, "", "")); w.Code != 401 {
		t.Errorf("without a session: %d", w.Code)
	}
	w := serve(h, request("GET", DefaultFeaturesPath, "", "a"))
	if w.Code != 200 || w.Body.String() != `{"components":["erp/sales"]}` || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("with a session: %d %q", w.Code, w.Body.String())
	}
	id.refuse = errSessionEnded
	if w := serve(h, request("GET", DefaultFeaturesPath, "", "z")); w.Code != 401 {
		t.Errorf("an ended session: %d", w.Code)
	}
	if c.calls() != 0 {
		t.Error("features never reach a component")
	}
}

// The messages of be.session.v1, against bytes written out by hand from the protobuf encoding.
func TestTheWireMessages(t *testing.T) {
	if got := string(encodeExchange("ab", true)); got != "\x0a\x02ab\x10\x01" {
		t.Errorf("ExchangeRequest %q", got)
	}
	if got := string(encodeExchange("ab", false)); got != "\x0a\x02ab" {
		t.Errorf("ExchangeRequest without renew %q", got)
	}
	if got := string(encodeEnded(&cursor{Impl: "i", Epoch: "1.2", Seq: 300}, 500)); got !=
		"\x0a\x0b\x0a\x01i\x12\x031.2\x18\xac\x02\x10\xf4\x03" { // the cursor: 3 + 5 + 3 bytes
		t.Errorf("EndedRequest %q", got)
	}
	r, err := decodeExchange([]byte("\x0a\x03tok\x10\x96\x01\x1a\x01p\x20\x02\x2a\x01z"))
	if err != nil || r.AccessToken != "tok" || r.ExpiresAtMs != 150 || r.Principal != "p" || r.SessionUntilMs != 2 {
		t.Errorf("ExchangeResponse %+v %v (an unknown field 5 skipped)", r, err)
	}
	e, err := decodeEnded([]byte("\x0a\x01a\x0a\x01b\x12\x07\x0a\x01i\x18\x05\x10\x00\x18\x01"))
	if err != nil || len(e.SessionDigests) != 2 || e.Next == nil || e.Next.Impl != "i" || e.Next.Seq != 5 || !e.Reset {
		t.Errorf("EndedResponse %+v %v", e, err)
	}
	if _, err := decodeEnded([]byte("\x0a\x05ab")); err == nil {
		t.Error("a truncated field is malformed")
	}
}
