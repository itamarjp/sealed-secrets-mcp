package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const issuer = "sealed-secrets-mcp"

// signer issues and verifies short-lived HS256 tokens. Possession of the
// signing key (in practice: `kubectl exec` into the pod) is what grants the
// right to mint tokens. Rotating the key revokes every token at once.
type signer struct {
	key      []byte
	audience string
	maxTTL   time.Duration
}

func loadSigner(keyFile, audience string, maxTTL time.Duration) (*signer, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	key = []byte(strings.TrimSpace(string(key)))
	if len(key) < 32 {
		return nil, errors.New("signing key must be at least 32 bytes")
	}
	if audience == "" {
		return nil, errors.New("SEAL_AUDIENCE (the public MCP URL) is required")
	}
	return &signer{key: key, audience: audience, maxTTL: maxTTL}, nil
}

func (s *signer) issue(client string, ttl time.Duration) (string, error) {
	if !validName(client) {
		return "", errors.New("client must be a short lowercase name, e.g. codex")
	}
	if ttl <= 0 || ttl > s.maxTTL {
		return "", fmt.Errorf("ttl must be between 0 and %s", s.maxTTL)
	}
	jti := make([]byte, 8)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   client,
		Audience:  jwt.ClaimStrings{s.audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        hex.EncodeToString(jti),
	}).SignedString(s.key)
}

func (s *signer) verify(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	var c jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) { return s.key, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(s.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	// Reject tokens minted with a longer lifetime than currently allowed,
	// so lowering SEAL_MAX_TTL also shortens tokens already in circulation.
	if c.IssuedAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) > s.maxTTL {
		return nil, fmt.Errorf("%w: lifetime exceeds limit", auth.ErrInvalidToken)
	}
	return &auth.TokenInfo{UserID: c.Subject, Expiration: c.ExpiresAt.Time}, nil
}

// clientFrom returns the token subject for audit logs.
func clientFrom(ctx context.Context) string {
	if ti := auth.TokenInfoFromContext(ctx); ti != nil {
		return ti.UserID
	}
	return "unknown"
}
