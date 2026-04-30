package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

var resourceDefs = []map[string]any{
	{
		"uri":         "zeerak://status",
		"name":        "Stager status",
		"description": "Current stager state (idle | pending | confirmed | rolled-back) and rollback deadline.",
		"mimeType":    "application/json",
	},
	{
		"uri":         "zeerak://ruleset/live",
		"name":        "Live nftables ruleset",
		"description": "Output of `nft list ruleset` — every table on the host, including those Zeerak does not own.",
		"mimeType":    "text/plain",
	},
}

func (s *Server) handleResourcesList() any {
	return map[string]any{"resources": resourceDefs}
}

type resourceReadParams struct {
	URI string `json:"uri"`
}

func (s *Server) handleResourcesRead(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p resourceReadParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: errParams, Message: "invalid params", Data: err.Error()}
	}
	switch p.URI {
	case "zeerak://status":
		st, err := s.daemon.Status(ctx)
		if err != nil {
			return nil, &rpcError{Code: errInternal, Message: "fetch status", Data: err.Error()}
		}
		body, _ := json.Marshal(st)
		return map[string]any{
			"contents": []map[string]any{{"uri": p.URI, "mimeType": "application/json", "text": string(body)}},
		}, nil
	case "zeerak://ruleset/live":
		text, err := s.daemon.LiveRuleset(ctx)
		if err != nil {
			return nil, &rpcError{Code: errInternal, Message: "fetch ruleset", Data: err.Error()}
		}
		return map[string]any{
			"contents": []map[string]any{{"uri": p.URI, "mimeType": "text/plain", "text": text}},
		}, nil
	}
	return nil, &rpcError{Code: errParams, Message: "unknown resource", Data: fmt.Sprintf("uri=%s", p.URI)}
}
