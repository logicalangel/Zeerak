package mcp

import (
	"io"
	"net/http"
)

// HTTPHandler returns an http.Handler that accepts a single JSON-RPC 2.0
// request per POST and returns the response in the body.
//
// This is a deliberately simple subset of MCP's "Streamable HTTP" — no SSE,
// no session ids, no batched requests. Sufficient for v0 read-only usage
// (curl, simple LLM integrations); the bidirectional streaming variant
// lands with the v0.3 staging tools.
//
// GET requests return a tiny info page so clients/humans can sanity-check
// the endpoint.
func (s *Server) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(`zeerak-mcp — POST a JSON-RPC 2.0 request body to this endpoint.
methods: initialize, tools/list, tools/call, resources/list, resources/read
`))
			return
		case http.MethodPost:
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			resp, isNotif := s.Handle(r.Context(), body)
			w.Header().Set("Content-Type", "application/json")
			if isNotif {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_, _ = w.Write(resp)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
