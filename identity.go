package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// identity is the identity member as the edge uses it: SessionService (be-protocol P8.28).
type identity interface {
	Exchange(ctx context.Context, digest string, renew bool) (exchangeResponse, error)
	Ended(ctx context.Context, after *cursor, limit uint32) (endedResponse, error)
}

// errSessionEnded is the identity member's SESSION_ENDED (gRPC UNAUTHENTICATED); any other failure means the member
// cannot answer now (P11.4).
var errSessionEnded = errors.New("the session has ended")

// grpcIdentity calls SessionService over HTTP/2 with the edge's service certificate (P8.5): gRPC framing by hand.
// The TLS configuration is static: in Yaegi a standard-library callback into interpreted code (GetClientCertificate,
// VerifyConnection) panics inside the handshake and takes Traefik down with it, so instead of callbacks a changed
// certificate file builds a new transport (rotation without a restart).
type grpcIdentity struct {
	base, serverName string
	files            *certFiles

	mu     sync.Mutex
	stamp  string
	client *http.Client
}

// callTimeout bounds one call to the identity member.
const callTimeout = 5 * time.Second

// dnsName is the name a component's certificate carries for clients that check host names (P8.5).
func dnsName(deployment, component string) string {
	return strings.ReplaceAll(component, "/", ".") + ".component." + deployment
}

func newGRPCIdentity(address, component, deployment, certFile, keyFile, caFile string) (*grpcIdentity, error) {
	g := &grpcIdentity{base: "https://" + address, serverName: dnsName(deployment, component),
		files: &certFiles{cert: certFile, key: keyFile, ca: caFile}}
	if _, err := g.httpClient(); err != nil {
		return nil, err
	}
	return g, nil
}

// httpClient is the client for the current certificate files; the standard library verifies the identity member's
// chain against the deployment's root and its name against the identity component's (P8.5).
func (g *grpcIdentity) httpClient() (*http.Client, error) {
	pair, roots, stamp, err := g.files.load()
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.client != nil && stamp == g.stamp {
		return g.client, nil
	}
	if g.client != nil {
		g.client.CloseIdleConnections()
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: g.serverName, RootCAs: roots,
		Certificates: []tls.Certificate{*pair}}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: callTimeout}
	g.client, g.stamp = &http.Client{Transport: tr}, stamp
	return g.client, nil
}

// certFiles holds the edge's certificate, key and the deployment's trust root, re-read when a file changes.
type certFiles struct {
	cert, key, ca string

	mu    sync.Mutex
	stamp string
	pair  *tls.Certificate
	roots *x509.CertPool
}

// load returns the files' contents and a stamp that changes when one of them does.
func (f *certFiles) load() (*tls.Certificate, *x509.CertPool, string, error) {
	stamp := ""
	for _, p := range []string{f.cert, f.key, f.ca} {
		st, err := os.Stat(p)
		if err != nil {
			return nil, nil, "", err
		}
		stamp += st.ModTime().String() + strconv.FormatInt(st.Size(), 10) + "|"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if stamp == f.stamp && f.pair != nil {
		return f.pair, f.roots, stamp, nil
	}
	pair, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("the edge's service certificate: %w", err)
	}
	pem, err := os.ReadFile(f.ca)
	if err != nil {
		return nil, nil, "", fmt.Errorf("the deployment's trust root: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, nil, "", errors.New("the deployment's trust root: no certificate")
	}
	f.stamp, f.pair, f.roots = stamp, &pair, roots
	return f.pair, f.roots, stamp, nil
}

// call sends one unary call and returns the reply message.
func (g *grpcIdentity) call(ctx context.Context, method string, msg []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	frame := make([]byte, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(msg)))
	copy(frame[5:], msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.base+"/be.session.v1.SessionService/"+method,
		bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("grpc-timeout", strconv.FormatInt(callTimeout.Milliseconds(), 10)+"m")
	client, err := g.httpClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	status := resp.Trailer.Get("Grpc-Status")
	if status == "" {
		status = resp.Header.Get("Grpc-Status") // a trailers-only answer
	}
	if status != "0" {
		code, _ := strconv.Atoi(status)
		if code == 16 { // UNAUTHENTICATED: SESSION_ENDED is the only refusal of this kind SessionService answers
			return nil, errSessionEnded
		}
		message, _ := url.PathUnescape(resp.Trailer.Get("Grpc-Message") + resp.Header.Get("Grpc-Message"))
		return nil, fmt.Errorf("%s: gRPC status %q: %s", method, status, message)
	}
	if len(body) < 5 || body[0] != 0 {
		return nil, fmt.Errorf("%s: no uncompressed reply message", method)
	}
	n := binary.BigEndian.Uint32(body[1:5])
	if uint64(len(body)-5) < uint64(n) {
		return nil, fmt.Errorf("%s: a truncated reply", method)
	}
	return body[5 : 5+n], nil
}

func (g *grpcIdentity) Exchange(ctx context.Context, digest string, renew bool) (exchangeResponse, error) {
	b, err := g.call(ctx, "Exchange", encodeExchange(digest, renew))
	if err != nil {
		return exchangeResponse{}, err
	}
	return decodeExchange(b)
}

func (g *grpcIdentity) Ended(ctx context.Context, after *cursor, limit uint32) (endedResponse, error) {
	b, err := g.call(ctx, "Ended", encodeEnded(after, limit))
	if err != nil {
		return endedResponse{}, err
	}
	return decodeEnded(b)
}
