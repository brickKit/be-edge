package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	edge "github.com/brickKit/be-edge/v3"
	protocol "github.com/brickKit/be-protocol/v3"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func digest(cookie string) string {
	sum := sha256.Sum256([]byte(cookie))
	return hex.EncodeToString(sum[:])
}

// scripted is the component behind the edge: answers from a list ("200", "TOKEN_STALE", "timeout" as a 504 the
// edge passes on), and the requests it got.
type scripted struct {
	mu      sync.Mutex
	answers []string
	tokens  []string
}

func (s *scripted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	s.mu.Lock()
	s.tokens = append(s.tokens, r.Header.Get("Authorization"))
	a := "200"
	if len(s.answers) > 0 {
		a, s.answers = s.answers[0], s.answers[1:]
	}
	s.mu.Unlock()
	switch a {
	case "TOKEN_STALE":
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"status":401,"reason":"TOKEN_STALE","domain":"be"}`))
	case "timeout":
		w.WriteHeader(504)
	default:
		code, _ := strconv.Atoi(a)
		w.WriteHeader(code)
	}
}

// newEdge is the plugin as Traefik builds it (New), in front of next, talking to the fake identity member at addr.
func newEdge(t *testing.T, w *sectest.World, addr string, next http.Handler, poll string) http.Handler {
	cert, key, ca := w.Certs(t, "infra/edge")
	cfg := edge.CreateConfig()
	cfg.IdentityAddress, cfg.IdentityComponent, cfg.Deployment = addr, "infra/iam-casdoor", w.Deployment
	cfg.CertFile, cfg.KeyFile, cfg.CAFile = cert, key, ca
	if poll != "" {
		cfg.PollInterval = poll
	}
	h, err := edge.New(context.Background(), next, cfg, "be-edge")
	require.NoError(t, err)
	return h
}

// The edge-flow vectors (P11.1-P11.4, P11.7) through the plugin's own entry, over gRPC and mTLS to a grpc-go
// SessionService: what the browser gets, how often the component and the identity member were called.
func TestEdgeFlowVectors(t *testing.T) {
	raw, err := fs.ReadFile(protocol.Vectors, "vectors/edge-flow.json")
	require.NoError(t, err)
	var v struct {
		Cases []struct {
			ID        string
			Method    string
			Cookie    bool
			Headers   map[string]string
			BodyBytes int `json:"body_bytes"`
			Cache     string
			Exchange  []string
			Answers   []string
			Expect    struct {
				Browser   string
				Forwarded int
				Exchanges int
				RenewIdle *bool `json:"renew_idle"`
			}
		}
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Cases)
	w := sectest.New(t)
	iam, addr := serveIAM(t, w, "infra/iam-casdoor")
	comp := &scripted{}
	h := newEdge(t, w, addr, comp, "1h") // no pulls during the cases
	// the poller's first pull (no cursor: reset) clears the cache once at start; let it happen before warming
	require.Eventually(t, func() bool { iam.mu.Lock(); defer iam.mu.Unlock(); return len(iam.callers) > 0 },
		2*time.Second, 10*time.Millisecond)
	for _, c := range v.Cases {
		cookie := "cookie-" + c.ID
		d := digest(cookie)
		if c.Cache == "hit" && c.Cookie { // warm the cache: one exchange and one request first
			iam.script(d, "ok")
			comp.answers = []string{"200"}
			req := httptest.NewRequest("GET", "/warm", nil)
			req.AddCookie(&http.Cookie{Name: "be_session", Value: cookie})
			h.ServeHTTP(httptest.NewRecorder(), req)
		}
		iam.mu.Lock()
		before, renewsBefore := iam.n, len(iam.renews[d])
		iam.mu.Unlock()
		iam.script(d, c.Exchange...)
		comp.mu.Lock()
		comp.answers, comp.tokens = append([]string(nil), c.Answers...), nil
		comp.mu.Unlock()
		var body io.Reader
		if c.BodyBytes > 0 {
			body = strings.NewReader(strings.Repeat("x", c.BodyBytes))
		}
		req := httptest.NewRequest(c.Method, "/api/x", body)
		for k, val := range c.Headers {
			req.Header.Set(k, val)
		}
		if c.Cookie {
			req.AddCookie(&http.Cookie{Name: "be_session", Value: cookie})
		}
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		got := strconv.Itoa(resp.Code)
		if c.Expect.Browser == "timeout" {
			got = map[bool]string{true: "timeout", false: got}[resp.Code == 504]
		} else if _, err := strconv.Atoi(c.Expect.Browser); err != nil {
			var p struct{ Reason string }
			_ = json.Unmarshal(resp.Body.Bytes(), &p)
			got = p.Reason
		}
		iam.mu.Lock()
		exchanges, renews := iam.n-before, iam.renews[d][renewsBefore:]
		iam.mu.Unlock()
		assert.Equal(t, c.Expect.Browser, got, c.ID)
		assert.Equal(t, c.Expect.Forwarded, len(comp.tokens), c.ID+": forwarded")
		assert.Equal(t, c.Expect.Exchanges, exchanges, c.ID+": exchanges")
		if c.Expect.RenewIdle != nil {
			for _, r := range renews {
				assert.Equal(t, *c.Expect.RenewIdle, r, c.ID+": renew_idle")
			}
		}
	}
	for _, c := range iam.callers {
		require.Equal(t, "infra/edge", c, "the identity member saw the edge's service identity")
	}
	require.NotEmpty(t, iam.callers, "precondition: the cases reached the identity member")
}

// P8.5: the edge checks the identity member's certificate; another component's is refused, the session kept.
func TestAServerWithAnotherIdentityIsRefused(t *testing.T) {
	w := sectest.New(t)
	iam, addr := serveIAM(t, w, "infra/authz")
	comp := &scripted{}
	h := newEdge(t, w, addr, comp, "1h")
	req := httptest.NewRequest("GET", "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: "be_session", Value: "c"})
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 503, resp.Code)
	assert.Contains(t, resp.Body.String(), `"dependency":"iam"`)
	assert.Empty(t, iam.callers, "nothing reached the impostor's methods")
	assert.Empty(t, comp.tokens)
}

// P11.5: the poller reads the ended sessions and the next request of an ended session exchanges again.
func TestThePollerDropsEndedSessions(t *testing.T) {
	w := sectest.New(t)
	iam, addr := serveIAM(t, w, "infra/iam-casdoor")
	comp := &scripted{}
	h := newEdge(t, w, addr, comp, "50ms")
	get := func(cookie string) int {
		req := httptest.NewRequest("GET", "/api/x", nil)
		req.AddCookie(&http.Cookie{Name: "be_session", Value: cookie})
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		return resp.Code
	}
	require.Eventually(t, func() bool { iam.mu.Lock(); defer iam.mu.Unlock(); return len(iam.callers) > 0 },
		2*time.Second, 10*time.Millisecond, "precondition: the poller started (its first pull, without a cursor)")
	require.Equal(t, 200, get("a"))
	require.Equal(t, 200, get("b"))
	iam.mu.Lock()
	iam.ended = []string{digest("a")}
	n := iam.n
	iam.mu.Unlock()
	require.Eventually(t, func() bool { iam.mu.Lock(); defer iam.mu.Unlock(); return iam.ended == nil },
		2*time.Second, 10*time.Millisecond, "the poller read the page")
	time.Sleep(20 * time.Millisecond) // the page applied
	get("a")
	get("b")
	iam.mu.Lock()
	defer iam.mu.Unlock()
	assert.Equal(t, n+1, iam.n, "only the ended session exchanged again")
}

// P8.5 (files can rotate): after the edge's certificate files are replaced, the next connection presents the new one.
func TestARotatedCertificateIsUsed(t *testing.T) {
	w := sectest.New(t)
	iam, addr := serveIAM(t, w, "infra/iam-casdoor")
	cert, key, ca := w.Certs(t, "infra/edge")
	cfg := edge.CreateConfig()
	cfg.IdentityAddress, cfg.IdentityComponent, cfg.Deployment = addr, "infra/iam-casdoor", w.Deployment
	cfg.CertFile, cfg.KeyFile, cfg.CAFile, cfg.PollInterval = cert, key, ca, "1h"
	h, err := edge.New(context.Background(), &scripted{}, cfg, "be-edge")
	require.NoError(t, err)
	get := func(cookie string) {
		req := httptest.NewRequest("GET", "/api/x", nil)
		req.AddCookie(&http.Cookie{Name: "be_session", Value: cookie})
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	get("a")
	newCert, newKey, _ := w.Certs(t, "infra/edge")
	time.Sleep(10 * time.Millisecond) // a later modification time
	for from, to := range map[string]string{newCert: cert, newKey: key} {
		b, err := os.ReadFile(from)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(to, b, 0o600))
	}
	get("b")
	iam.mu.Lock()
	defer iam.mu.Unlock()
	require.GreaterOrEqual(t, len(iam.serials), 2)
	first, last := iam.serials[0], iam.serials[len(iam.serials)-1]
	assert.NotEmpty(t, first)
	assert.NotEqual(t, first, last, "the rotated certificate was presented")
}
