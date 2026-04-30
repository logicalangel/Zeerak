package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// Tool catalogue. Schemas use the JSON Schema subset MCP clients understand.
var toolDefs = []map[string]any{
	{
		"name":        "explain_rule",
		"description": "Translate an nftables rule expression (e.g. \"tcp dport 22 accept\") into plain English. No daemon access required.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"expr": map[string]any{
					"type":        "string",
					"description": "Raw nft rule expression, e.g. 'ip saddr 10.0.0.0/8 tcp dport 22 accept'.",
				},
			},
			"required": []string{"expr"},
		},
	},
	{
		"name":        "simulate_packet",
		"description": "Heuristic verdict prediction: walks the live nftables ruleset for the given hook and reports the first matching rule's verdict. Best-effort; not a full nftables VM.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"hook":     map[string]any{"type": "string", "enum": []string{"input", "forward", "output"}, "default": "input"},
				"protocol": map[string]any{"type": "string", "enum": []string{"tcp", "udp", "icmp", "icmpv6"}},
				"saddr":    map[string]any{"type": "string", "description": "Source IP (v4 or v6)."},
				"daddr":    map[string]any{"type": "string", "description": "Destination IP."},
				"sport":    map[string]any{"type": "integer"},
				"dport":    map[string]any{"type": "integer"},
				"iif":      map[string]any{"type": "string", "description": "Input interface name."},
				"oif":      map[string]any{"type": "string", "description": "Output interface name."},
			},
			"required": []string{"protocol"},
		},
	},
}

func (s *Server) handleToolsList() any {
	return map[string]any{"tools": toolDefs}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) handleToolsCall(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p toolCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: errParams, Message: "invalid params", Data: err.Error()}
	}
	switch p.Name {
	case "explain_rule":
		var args struct{ Expr string `json:"expr"` }
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return nil, &rpcError{Code: errParams, Message: "invalid arguments", Data: err.Error()}
		}
		if args.Expr == "" {
			return toolError("expr is required"), nil
		}
		return map[string]any{"content": textContent(ExplainRule(args.Expr))}, nil

	case "simulate_packet":
		var pkt Packet
		if err := json.Unmarshal(p.Arguments, &pkt); err != nil {
			return nil, &rpcError{Code: errParams, Message: "invalid arguments", Data: err.Error()}
		}
		if pkt.Protocol == "" {
			return toolError("protocol is required"), nil
		}
		text, err := s.daemon.LiveRuleset(ctx)
		if err != nil {
			return toolError(fmt.Sprintf("fetch live ruleset: %v", err)), nil
		}
		res := SimulatePacket(text, pkt)
		out, _ := json.MarshalIndent(res, "", "  ")
		return map[string]any{"content": textContent(string(out))}, nil
	}
	return nil, &rpcError{Code: errMethod, Message: "unknown tool", Data: p.Name}
}

// toolError formats an in-tool failure (per MCP, errors are reported as
// content with isError=true rather than as JSON-RPC errors).
func toolError(msg string) map[string]any {
	return map[string]any{
		"isError": true,
		"content": textContent(msg),
	}
}
