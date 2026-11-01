package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

// hybridVerifier accepts either existing server-issued HS256 JWTs or Pocket ID
// RS256 access tokens. Identity prefixes are set only after verification; they
// are not read from untrusted token claims.
type hybridVerifier struct {
	legacy *signer
	pocket *pocketVerifier
}

func (h *hybridVerifier) verify(ctx context.Context, raw string, r *http.Request) (*auth.TokenInfo, error) {
	parser := jwt.NewParser()
	var claims jwt.RegisteredClaims
	untrusted, _, err := parser.ParseUnverified(raw, &claims)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed token", auth.ErrInvalidToken)
	}
	var info *auth.TokenInfo
	switch untrusted.Method.Alg() {
	case "HS256":
		info, err = h.legacy.verify(ctx, raw, r)
		if err == nil {
			info.UserID = "jwt:" + info.UserID
		}
	case "RS256":
		info, err = h.pocket.verify(ctx, raw, r)
		if err == nil {
			info.UserID = "pocketid:" + info.UserID
		}
	default:
		return nil, fmt.Errorf("%w: unsupported token algorithm", auth.ErrInvalidToken)
	}
	if err != nil {
		return nil, err
	}
	if info == nil || strings.TrimSpace(info.UserID) == "" {
		return nil, fmt.Errorf("%w: missing identity", auth.ErrInvalidToken)
	}
	return info, nil
}
