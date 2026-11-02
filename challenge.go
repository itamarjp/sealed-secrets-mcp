package main

import (
	"fmt"
	"net/http"
	"strings"
)

// oauthChallenge makes the 401 Bearer challenge on /mcp tell OAuth clients
// exactly which scope to request (RFC 6750 §3, MCP authorization spec "scope
// selection strategy").
//
// Without a scope in the challenge, MCP clients such as claude.ai fall back to
// every entry in the protected-resource metadata `scopes_supported`. When
// rotation is enabled that includes seal:rotate, and Pocket ID rejects the whole
// authorization request with invalid_scope unless the client was granted every
// requested permission. Clients that request no scope at all receive a token
// without seal:existing, which the verifier then rejects, so the connection
// never completes either way.
//
// The SDK's RequireBearerTokenOptions.Scopes cannot be used for this: it also
// enforces those scopes on every token, which would lock out the legacy HS256
// clients in hybrid mode. The challenge is therefore rewritten on the way out.
func oauthChallenge(resourceMetadataURL, scope string) func(http.Handler) http.Handler {
	params := []string{fmt.Sprintf("resource_metadata=%q", resourceMetadataURL)}
	if scope != "" {
		params = append(params, fmt.Sprintf("scope=%q", scope))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := params
			if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
				p = append([]string{`error="invalid_token"`}, params...)
			}
			next.ServeHTTP(&challengeWriter{ResponseWriter: w, challenge: "Bearer " + strings.Join(p, ", ")}, r)
		})
	}
}

type challengeWriter struct {
	http.ResponseWriter
	challenge   string
	wroteHeader bool
}

func (c *challengeWriter) WriteHeader(code int) {
	if !c.wroteHeader && code == http.StatusUnauthorized {
		c.Header().Set("WWW-Authenticate", c.challenge)
	}
	c.wroteHeader = true
	c.ResponseWriter.WriteHeader(code)
}

func (c *challengeWriter) Write(b []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach Flush on the real writer, which
// the streamable HTTP transport needs for SSE responses.
func (c *challengeWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *challengeWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
