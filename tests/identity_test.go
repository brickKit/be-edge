package tests

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/brickKit/be-sdk-go/v3/sessionpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// fakeIAM is SessionService as grpc-go serves it, over the deployment's mTLS: scripted answers per session digest
// ("ok", "ended", "unavailable"), the ended sessions from a queue, and what it saw (the callers, renew_idle).
type fakeIAM struct {
	sessionpb.UnimplementedSessionServiceServer
	deployment string

	mu      sync.Mutex
	answers map[string][]string
	n       int
	callers []string
	serials []string // the serial number of each call's client certificate
	renews  map[string][]bool
	ended   []string
	seq     uint64
}

func (f *fakeIAM) caller(ctx context.Context) {
	c, _ := identity.Caller(ctx, f.deployment)
	serial := ""
	if p, ok := peer.FromContext(ctx); ok {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
			serial = ti.State.PeerCertificates[0].SerialNumber.String()
		}
	}
	f.mu.Lock()
	f.callers, f.serials = append(f.callers, c), append(f.serials, serial)
	f.mu.Unlock()
}

func (f *fakeIAM) Exchange(ctx context.Context, in *sessionpb.ExchangeRequest) (*sessionpb.ExchangeResponse, error) {
	f.caller(ctx)
	f.mu.Lock()
	d := in.GetSessionDigest()
	a := "ok"
	if q := f.answers[d]; len(q) > 0 {
		a, f.answers[d] = q[0], q[1:]
	}
	f.renews[d] = append(f.renews[d], in.GetRenewIdle())
	f.n++
	n := f.n
	f.mu.Unlock()
	switch a {
	case "ended":
		return nil, errs.New(errs.ReasonSessionEnded, "no live session").GRPCStatus().Err()
	case "unavailable":
		return nil, errs.New(errs.ReasonDependencyUnavailable, "db").GRPCStatus().Err()
	}
	now := time.Now()
	return &sessionpb.ExchangeResponse{AccessToken: "tok-" + d[:8] + "-" + itoa(n), Principal: "p",
		ExpiresAtMs: now.Add(5 * time.Minute).UnixMilli(), SessionUntilMs: now.Add(time.Hour).UnixMilli()}, nil
}

func (f *fakeIAM) Ended(ctx context.Context, in *sessionpb.EndedRequest) (*sessionpb.EndedResponse, error) {
	f.caller(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if in.GetAfter() == nil {
		return &sessionpb.EndedResponse{Reset_: true, Next: &sessionpb.Cursor{Impl: "fake", Epoch: "1.1", Seq: f.seq}}, nil
	}
	out := &sessionpb.EndedResponse{SessionDigests: f.ended}
	f.seq += uint64(len(f.ended))
	f.ended = nil
	out.Next = &sessionpb.Cursor{Impl: "fake", Epoch: "1.1", Seq: f.seq}
	return out, nil
}

func (f *fakeIAM) script(digest string, answers ...string) {
	f.mu.Lock()
	f.answers[digest] = append(f.answers[digest], answers...)
	f.mu.Unlock()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

// serveIAM starts the fake identity member with the certificate of component (infra/iam-casdoor, or another one
// for the wrong-identity case).
func serveIAM(t *testing.T, w *sectest.World, component string) (*fakeIAM, string) {
	f := &fakeIAM{deployment: w.Deployment, answers: map[string][]string{}, renews: map[string][]bool{}}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(w.TLS(t, component).ServerConfig())))
	sessionpb.RegisterSessionServiceServer(srv, f)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return f, ln.Addr().String()
}
