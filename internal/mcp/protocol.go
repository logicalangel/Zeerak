// Package mcp implements a minimal Model Context Protocol server (v0) for
// Zeerak. It exposes the firewall as MCP resources and tools so LLM agents
// can read the current state and reason about rules. Per VISION.md §9.
//
// What's implemented (v0.2 — read-only):
//
//   Resources
//     zeerak://status        JSON: stager state + deadline
//     zeerak://ruleset/live  text: `nft list ruleset` output
//
//   Tools
//     explain_rule(expr)              — plain-English summary of a rule
//     simulate_packet({...})          — heuristic verdict prediction
//
// Transports: stdio (line-delimited JSON-RPC 2.0) and HTTP. We do NOT
// implement Streamable-HTTP/SSE bidirectional messaging in v0; that lands
// with the v1 staging tools (VISION.md §10 v0.3).
//
// Wire format follows MCP spec methods: initialize, tools/list, tools/call,
// resources/list, resources/read, plus the "notifications/initialized"
// notification.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// Protocol version we advertise. MCP clients negotiate against this.
const ProtocolVersion = "2024-11-05"

// rpcRequest is a JSON-RPC 2.0 request or notification.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcResponse is a JSON-RPC 2.0 response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	errParse     = -32700
	errInvalid   = -32600
	errMethod    = -32601
	errParams    = -32602
	errInternal  = -32603
)

// DaemonClient is the read-only daemon view the MCP server needs.
// Implemented by *cliclient.Client; tests provide a fake.
type DaemonClient interface {
	Status(ctx context.Context) (map[string]any, error)
	LiveRuleset(ctx context.Context) (string, error)
}

// Server wires resources and tools. Construct with New, then Serve over a
// transport.
type Server struct {
	daemon DaemonClient
	info   serverInfo
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// New returns an MCP server backed by daemon.
func New(daemon DaemonClient, version string) *Server {
	return &Server{
		daemon: daemon,
		info:   serverInfo{Name: "zeerak-mcp", Version: version},
	}
}

// Handle dispatches a single JSON-RPC request. Notifications (id absent)
// return a nil response. Returns (response, isNotification).
func (s *Server) Handle(ctx context.Context, raw []byte) ([]byte, bool) {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return mustMarshal(errorResponse(nil, errParse, "parse error", err.Error())), false
	}
	if req.JSONRPC != "2.0" {
		return mustMarshal(errorResponse(req.ID, errInvalid, "invalid request", "jsonrpc must be 2.0")), false
	}

	isNotif := len(req.ID) == 0
	result, rerr := s.dispatch(ctx, req.Method, req.Params)
	if isNotif {
		return nil, true
	}
	if rerr != nil {
		return mustMarshal(errorResponse(req.ID, rerr.Code, rerr.Message, rerr.Data)), false
	}
	return mustMarshal(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}), false
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		return s.handleInitialize(params)
	case "notifications/initialized", "initialized":
		return nil, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return s.handleToolsList(), nil
	case "tools/call":
		return s.handleToolsCall(ctx, params)
	case "resources/list":
		return s.handleResourcesList(), nil
	case "resources/read":
		return s.handleResourcesRead(ctx, params)
	}
	return nil, &rpcError{Code: errMethod, Message: "method not found", Data: method}
}

// --- initialize -------------------------------------------------------------

func (s *Server) handleInitialize(_ json.RawMessage) (any, *rpcError) {
	return map[string]any{
		"protocolVersion": ProtocolVersion,
		"serverInfo":      s.info,
		"capabilities": map[string]any{
			"tools":     map[string]any{"listChanged": false},
			"resources": map[string]any{"listChanged": false, "subscribe": false},
		},
		"instructions": "Zeerak MCP — read-only firewall introspection. Use resources/read for state, tools/call explain_rule|simulate_packet to reason about traffic.",
	}, nil
}

// --- helpers ----------------------------------------------------------------

func errorResponse(id json.RawMessage, code int, msg string, data any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg, Data: data}}
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Marshal of our own types should never fail; if it does, surface a
		// JSON-RPC parse-error envelope so clients see something.
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","error":{"code":%d,"message":%q}}`, errInternal, err.Error()))
	}
	return b
}

func textContent(text string) []map[string]any {
	return []map[string]any{{"type": "text", "text": text}}
}
