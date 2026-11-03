package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// interceptor writes the component's answer straight through, except a 401: that one is held to see whether it is
// TOKEN_STALE (the only answer the edge acts on, P11.3), then either dropped (replay) or released as it was.
type interceptor struct {
	w       http.ResponseWriter
	header  http.Header
	status  int
	held    bool // a 401, kept back
	body    bytes.Buffer
	started bool // the headers went out
}

func newInterceptor(w http.ResponseWriter) *interceptor {
	return &interceptor{w: w, header: http.Header{}}
}

func (i *interceptor) Header() http.Header { return i.header }

func (i *interceptor) WriteHeader(code int) {
	if i.status != 0 {
		return
	}
	i.status = code
	if code == http.StatusUnauthorized {
		i.held = true
		return
	}
	i.start()
}

func (i *interceptor) start() {
	dst := i.w.Header()
	for k, v := range i.header {
		dst[k] = v
	}
	i.w.WriteHeader(i.status)
	i.started = true
}

func (i *interceptor) Write(b []byte) (int, error) {
	if i.status == 0 {
		i.WriteHeader(http.StatusOK)
	}
	if i.held {
		return i.body.Write(b)
	}
	return i.w.Write(b)
}

// Flush passes a streaming component's flushes on (server-sent events, long downloads).
func (i *interceptor) Flush() {
	if i.held {
		return
	}
	if i.status == 0 {
		i.WriteHeader(http.StatusOK)
	}
	if f, ok := i.w.(http.Flusher); ok {
		f.Flush()
	}
}

// stale reports whether the answer is 401 TOKEN_STALE.
func (i *interceptor) stale() bool {
	if !i.held {
		return false
	}
	var p struct {
		Reason string `json:"reason"`
	}
	return json.Unmarshal(i.body.Bytes(), &p) == nil && p.Reason == "TOKEN_STALE"
}

// release sends what was held (a 401 that is not TOKEN_STALE), or finishes an answer that wrote nothing.
func (i *interceptor) release() {
	if i.status == 0 {
		i.WriteHeader(http.StatusOK)
	}
	if !i.held {
		return
	}
	i.start()
	_, _ = i.w.Write(i.body.Bytes())
}
