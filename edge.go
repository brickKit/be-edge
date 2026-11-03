// Package edge is the edge's session layer (be-protocol chapter 11): for a browser request with the session cookie
// it injects the session's access token, exchanged from the identity member's SessionService and cached per session;
// it replays the request once when the entry component answers TOKEN_STALE; state-changing requests need the
// BE-Request header; features goes to live sessions only; the sessions that ended are pulled by cursor. The package
// is a Traefik middleware plugin (Yaegi: standard library only); the same handler serves a sidecar for other edges.
package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config is the middleware's configuration (Traefik's dynamic configuration, or the sidecar's).
type Config struct {
	// IdentityAddress is the identity member's system surface, host:port; IdentityComponent its component ID (the
	// certificate it must present); Deployment the deployment ID.
	IdentityAddress   string `json:"identityAddress,omitempty"`
	IdentityComponent string `json:"identityComponent,omitempty"`
	Deployment        string `json:"deployment,omitempty"`
	// CertFile, KeyFile and CAFile are the edge's service identity infra/edge and the deployment's trust root.
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	CAFile   string `json:"caFile,omitempty"`
	// FeaturesFile is the deployment's features document (made by the assembly tool), served at FeaturesPath.
	FeaturesFile string `json:"featuresFile,omitempty"`
	FeaturesPath string `json:"featuresPath,omitempty"`
	// LogoutPath is the identity member's logout route: after it succeeds the session's token is dropped at once.
	LogoutPath string `json:"logoutPath,omitempty"`
	// ReplayLimit is B_replay in bytes; PollInterval is P_inv (a Go duration).
	ReplayLimit  int64  `json:"replayLimit,omitempty"`
	PollInterval string `json:"pollInterval,omitempty"`
	CookieName   string `json:"cookieName,omitempty"`
}

// The starting values (be-protocol chapter 11).
const (
	DefaultReplayLimit  = 1 << 20
	DefaultPollInterval = "1s"
	DefaultCookie       = "be_session"
	DefaultFeaturesPath = "/api/features"
	DefaultLogoutPath   = "/api/iam/logout"
)

// CreateConfig returns the default configuration.
func CreateConfig() *Config {
	return &Config{ReplayLimit: DefaultReplayLimit, PollInterval: DefaultPollInterval, CookieName: DefaultCookie,
		FeaturesPath: DefaultFeaturesPath, LogoutPath: DefaultLogoutPath}
}

// shared is one cache and one poller per identity member and certificate: every router's instance of the
// middleware, and every rebuild on a configuration reload, uses the same (P11.10).
var (
	sharedMu sync.Mutex
	shared   = map[string]*sessions{}
)

// New builds the middleware (Traefik calls it for every router that uses it, and again on every reload).
func New(_ context.Context, next http.Handler, cfg *Config, _ string) (http.Handler, error) {
	if cfg.IdentityAddress == "" || cfg.IdentityComponent == "" || cfg.Deployment == "" || cfg.CertFile == "" ||
		cfg.KeyFile == "" || cfg.CAFile == "" {
		return nil, errors.New("be-edge: identityAddress, identityComponent, deployment, certFile, keyFile and caFile are required")
	}
	every, err := time.ParseDuration(cfg.PollInterval)
	if err != nil || every <= 0 {
		return nil, fmt.Errorf("be-edge: pollInterval %q is not a positive duration", cfg.PollInterval)
	}
	key := strings.Join([]string{cfg.IdentityAddress, cfg.IdentityComponent, cfg.Deployment, cfg.CertFile}, "|")
	sharedMu.Lock()
	s, ok := shared[key]
	if !ok {
		id, err := newGRPCIdentity(cfg.IdentityAddress, cfg.IdentityComponent, cfg.Deployment, cfg.CertFile,
			cfg.KeyFile, cfg.CAFile)
		if err != nil {
			sharedMu.Unlock()
			return nil, fmt.Errorf("be-edge: %w", err)
		}
		s = newSessions(id)
		shared[key] = s
		go s.poll(context.Background(), every)
	}
	sharedMu.Unlock()
	log.Printf("be-edge: middleware built (shared cache reused: %v)", ok)
	return newHandler(next, cfg, s), nil
}

// handler is the middleware for one router.
type handler struct {
	next     http.Handler
	cfg      Config
	sessions *sessions
}

func newHandler(next http.Handler, cfg *Config, s *sessions) *handler {
	c := *cfg
	if c.ReplayLimit <= 0 {
		c.ReplayLimit = DefaultReplayLimit
	}
	if c.CookieName == "" {
		c.CookieName = DefaultCookie
	}
	if c.FeaturesPath == "" {
		c.FeaturesPath = DefaultFeaturesPath
	}
	if c.LogoutPath == "" {
		c.LogoutPath = DefaultLogoutPath
	}
	return &handler{next: next, cfg: c, sessions: s}
}

// digest is what the identity member keeps of a session cookie: its SHA-256 in lowercase hex (P8.28).
func digest(cookie string) string {
	sum := sha256.Sum256([]byte(cookie))
	return hex.EncodeToString(sum[:])
}

func changesState(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("Authorization") // a browser's own never reaches a component (P11.1)
	var d string
	if ck, err := r.Cookie(h.cfg.CookieName); err == nil && ck.Value != "" {
		d = digest(ck.Value)
	}
	if r.URL.Path == h.cfg.FeaturesPath && r.Method == http.MethodGet {
		h.features(w, r, d)
		return
	}
	if d == "" { // public routes, external callbacks: as they are
		h.next.ServeHTTP(w, r)
		return
	}
	if changesState(r.Method) && r.Header.Get("BE-Request") != "1" {
		problem(w, 403, "CSRF_HEADER_REQUIRED", "The request needs the BE-Request header", nil) // P11.2
		return
	}
	renew := r.Header.Get("BE-Polling") != "1"
	tok, err := h.sessions.token(r.Context(), d, renew)
	if err != nil {
		h.refused(w, err)
		return
	}
	body, replayable, err := buffer(r, h.cfg.ReplayLimit)
	if err != nil {
		problem(w, 400, "REQUEST_INVALID", "The request body could not be read", nil)
		return
	}
	first := newInterceptor(w)
	h.next.ServeHTTP(first, with(r, body, tok))
	if !first.stale() {
		first.release()
		if r.URL.Path == h.cfg.LogoutPath && first.status >= 200 && first.status < 300 {
			h.sessions.drop(d) // P11.6
		}
		return
	}
	// P11.3: the entry component refused the token before doing anything: a new token, the same request once
	h.sessions.drop(d)
	tok, err = h.sessions.exchange(r.Context(), d, renew)
	if err != nil {
		h.refused(w, err)
		return
	}
	if !replayable {
		problem(w, 503, "AUTHORIZATION_UNPROVABLE", "The request could not be confirmed; try again",
			map[string]string{"cause": "body_over_replay_limit"})
		return
	}
	again := newInterceptor(w)
	h.next.ServeHTTP(again, with(r, body, tok))
	if again.stale() {
		h.sessions.drop(d)
		problem(w, 401, "SESSION_ENDED", "The session has ended; log in again", nil)
		return
	}
	again.release()
}

// refused answers a failed exchange (P11.4).
func (h *handler) refused(w http.ResponseWriter, err error) {
	if err == errSessionEnded {
		problem(w, 401, "SESSION_ENDED", "The session has ended; log in again", nil)
		return
	}
	problem(w, 503, "DEPENDENCY_UNAVAILABLE", "The identity member cannot answer now; try again",
		map[string]string{"dependency": "iam"})
}

// features is the deployment's features document, for live sessions only (P11.8).
func (h *handler) features(w http.ResponseWriter, r *http.Request, d string) {
	if d == "" {
		problem(w, 401, "SESSION_ENDED", "The session has ended; log in again", nil)
		return
	}
	if _, err := h.sessions.token(r.Context(), d, r.Header.Get("BE-Polling") != "1"); err != nil {
		h.refused(w, err)
		return
	}
	b, err := os.ReadFile(h.cfg.FeaturesFile)
	if err != nil {
		problem(w, 503, "DEPENDENCY_UNAVAILABLE", "The features document is not available",
			map[string]string{"dependency": "features"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

// buffer reads the body up to limit so that it can be sent again; a larger body is streamed and not replayable.
func buffer(r *http.Request, limit int64) (body io.Reader, replayable bool, err error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true, nil
	}
	head, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(head)) <= limit {
		return bytes.NewReader(head), true, nil
	}
	return io.MultiReader(bytes.NewReader(head), r.Body), false, nil
}

// with is the request to forward: the token injected, the body (buffered, so a second one reads it again).
func with(r *http.Request, body io.Reader, token string) *http.Request {
	out := r.Clone(r.Context())
	out.Header.Set("Authorization", "Bearer "+token)
	if br, ok := body.(*bytes.Reader); ok {
		_, _ = br.Seek(0, io.SeekStart)
		out.Body = io.NopCloser(br)
		out.ContentLength = br.Size()
	} else if body != nil {
		out.Body = io.NopCloser(body)
	} else {
		out.Body = http.NoBody
	}
	return out
}

// problem writes the edge's own answer as the protocol's problem+json (P3.1).
func problem(w http.ResponseWriter, status int, reason, detail string, metadata map[string]string) {
	p := map[string]any{"type": "urn:be:be:" + reason, "title": reason, "status": status, "detail": detail,
		"reason": reason, "domain": "be", "trace_id": ""}
	if len(metadata) > 0 {
		p["metadata"] = metadata
	}
	w.Header().Set("Content-Type", "application/problem+json")
	if status == 503 {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}
