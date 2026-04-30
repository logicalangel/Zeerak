package mcp

import (
	"bufio"
	"context"
	"errors"
	"io"
)

// ServeStdio reads line-delimited JSON-RPC 2.0 from r and writes responses
// (one JSON object per line) to w. Blocks until ctx is cancelled or r is
// closed.
//
// MCP's official stdio transport uses newline-delimited JSON; that's what
// `claude mcp` and `mcp-cli --stdio` speak.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			resp, isNotif := s.Handle(ctx, line)
			if !isNotif {
				if _, werr := w.Write(append(resp, '\n')); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}
