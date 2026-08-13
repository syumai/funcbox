package dashboard

import (
	"bytes"
	"net/http"
)

// responseRecorder is a minimal in-memory http.ResponseWriter, just enough
// to capture what an internal/api handler writes when called in-process by
// internalAPIBinding (internalapi.go): no real network connection exists to
// write to, so the status/body just need to be buffered and read back.
type responseRecorder struct {
	status      int
	body        bytes.Buffer
	header      http.Header
	wroteHeader bool
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{status: http.StatusOK, header: make(http.Header)}
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(b)
}
