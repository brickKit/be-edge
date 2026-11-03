//go:build traefik

package tests

// The plugin in a real Traefik v3.0.4 (the assembly project's pinned image), loaded the way Traefik loads it (a local
// Yaegi plugin), in front of a recording backend, talking to the grpc-go fake identity member over mTLS. Needs Docker;
// the container uses the host network. Run: go test -tags traefik ./...

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const traefikImage = "traefik:v3.0.4@sha256:a208c74fd80a566d4ea376053bff73d31616d7af3f1465a7747b8b89ee34d97e"

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestThePluginInTraefik(t *testing.T) {
	w := sectest.New(t)
	iam, iamAddr := serveIAM(t, w, "infra/iam-casdoor")
	var mu sync.Mutex
	var seen []string
	answers := []string{}
	backend := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		a := "200"
		if len(answers) > 0 {
			a, answers = answers[0], answers[1:]
		}
		mu.Unlock()
		if a == "TOKEN_STALE" {
			rw.Header().Set("Content-Type", "application/problem+json")
			rw.WriteHeader(401)
			_, _ = rw.Write([]byte(`{"status":401,"reason":"TOKEN_STALE","domain":"be"}`))
			return
		}
		if r.Method == "POST" {
			rw.WriteHeader(201)
		}
		_, _ = rw.Write([]byte("backend"))
	})}
	bln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = backend.Serve(bln) }()
	t.Cleanup(func() { _ = backend.Close() })

	root, err := filepath.Abs("..")
	require.NoError(t, err)
	cert, key, ca := w.Certs(t, "infra/edge")
	dir := t.TempDir()
	port := freePort(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "traefik.yml"), []byte(fmt.Sprintf(`entryPoints:
  web:
    address: "127.0.0.1:%d"
providers:
  file:
    filename: %s/dynamic.yml
    watch: true
log:
  level: INFO
experimental:
  localPlugins:
    beedge:
      moduleName: github.com/brickKit/be-edge/v3
`, port, dir)), 0o644))
	dynamic := func(extra string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "dynamic.yml"), []byte(fmt.Sprintf(`http:
  routers:
    all:
      rule: PathPrefix(%s)
      entryPoints: [web]
      middlewares: [edge]
      service: backend
%s
  middlewares:
    edge:
      plugin:
        beedge:
          identityAddress: %q
          identityComponent: infra/iam-casdoor
          deployment: %q
          certFile: %q
          keyFile: %q
          caFile: %q
          pollInterval: 200ms
  services:
    backend:
      loadBalancer:
        servers:
          - url: http://%s
`, "`/`", extra, iamAddr, w.Deployment, cert, key, ca, bln.Addr().String())), 0o644))
	}
	dynamic("")
	name := fmt.Sprintf("be-edge-test-%d", port)
	certDir := filepath.Dir(cert)
	out, err := exec.Command("docker", "run", "-d", "--name", name, "--network", "host",
		"-v", dir+":"+dir+":ro", "-v", certDir+":"+certDir+":ro",
		"-v", root+":/plugins-local/src/github.com/brickKit/be-edge/v3:ro",
		traefikImage, "--configFile="+dir+"/traefik.yml").CombinedOutput()
	require.NoError(t, err, string(out))
	logs := func() string { b, _ := exec.Command("docker", "logs", name).CombinedOutput(); return string(b) }
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logs())
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	do := func(method, path, cookie string, headers ...string) (int, string) {
		req, _ := http.NewRequest(method, base+path, bytes.NewReader([]byte(`{"a":1}`)))
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "be_session", Value: cookie})
		}
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	require.Eventually(t, func() bool { c, _ := do("GET", "/x", ""); return c == 200 }, 60*time.Second,
		200*time.Millisecond, "Traefik loaded the plugin and routes")
	exchanges := func() int { iam.mu.Lock(); defer iam.mu.Unlock(); return iam.n }

	// P11.1: injected, cached
	code, _ := do("GET", "/x", "session-1", "Authorization", "Bearer forged")
	require.Equal(t, 200, code)
	do("GET", "/x", "session-1")
	mu.Lock()
	injected := seen[len(seen)-1]
	mu.Unlock()
	assert.True(t, strings.HasPrefix(injected, "Bearer tok-"+digest("session-1")[:8]), injected)
	assert.Equal(t, 1, exchanges(), "one exchange, then the cache")
	// P11.2
	code, body := do("POST", "/x", "session-1")
	assert.Equal(t, 403, code, body)
	assert.Contains(t, body, "CSRF_HEADER_REQUIRED")
	// P11.3: TOKEN_STALE replayed once with a new token
	mu.Lock()
	answers = []string{"TOKEN_STALE", "201"}
	n := len(seen)
	mu.Unlock()
	code, _ = do("POST", "/x", "session-1", "BE-Request", "1")
	assert.Equal(t, 201, code)
	mu.Lock()
	assert.Len(t, seen[n:], 2)
	assert.NotEqual(t, seen[n], seen[n+1])
	mu.Unlock()
	assert.Equal(t, 2, exchanges())
	// P11.5: an ended session is dropped by the poller
	iam.mu.Lock()
	iam.ended = []string{digest("session-1")}
	iam.mu.Unlock()
	require.Eventually(t, func() bool { iam.mu.Lock(); defer iam.mu.Unlock(); return iam.ended == nil }, 5*time.Second,
		50*time.Millisecond, "the poller read the page")
	time.Sleep(100 * time.Millisecond)
	do("GET", "/x", "session-1")
	assert.Equal(t, 3, exchanges(), "the ended session exchanged again")
	// P11.10: a configuration reload (Traefik builds the middleware again) keeps the cache
	built := strings.Count(logs(), "be-edge: middleware built")
	dynamic(`    other:
      rule: PathPrefix(` + "`/other`" + `)
      entryPoints: [web]
      service: backend`)
	require.Eventually(t, func() bool { return strings.Count(logs(), "be-edge: middleware built") > built }, 20*time.Second,
		200*time.Millisecond, "precondition: the reload built the middleware again")
	assert.Contains(t, logs(), "shared cache reused: true")
	do("GET", "/x", "session-1")
	assert.Equal(t, 3, exchanges(), "no exchange after the reload")
	// P11.9: no cookie, digest or token in Traefik's logs
	l := logs()
	for _, secret := range []string{"session-1", digest("session-1"), injected[len("Bearer "):]} {
		assert.NotContains(t, l, secret)
	}
}
