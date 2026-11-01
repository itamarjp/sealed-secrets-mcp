package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const pocketScope = "seal:existing"
const rotateScope = "seal:rotate"

// pocketVerifier validates resource-bound Pocket ID access tokens. The
// Kubernetes Role still limits which single named Secrets may be read.
type pocketVerifier struct {
	issuer, audience, allowedSub string
	http                         *http.Client
}

func newPocketVerifier(issuer, audience, subject string) (*pocketVerifier, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("SEAL_POCKET_ID_ISSUER must be a bare HTTPS origin")
	}
	a, err := url.Parse(audience)
	if err != nil || a.Scheme != "https" || a.Host == "" || a.User != nil || a.Fragment != "" {
		return nil, errors.New("SEAL_AUDIENCE must be a public HTTPS URL")
	}
	if subject == "" || strings.TrimSpace(subject) != subject {
		return nil, errors.New("SEAL_POCKET_ID_SUB must be the exact non-empty Pocket ID user subject")
	}
	return &pocketVerifier{issuer: issuer, audience: audience, allowedSub: subject, http: &http.Client{Timeout: 5 * time.Second}}, nil
}

type pocketClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

type pocketJWKS struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (p *pocketVerifier) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("missing token key ID")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.issuer+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Pocket ID JWKS status %d", resp.StatusCode)
	}
	var keys pocketJWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&keys); err != nil {
		return nil, err
	}
	for _, k := range keys.Keys {
		if k.Kid != kid || k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 || exponent < 3 || exponent%2 == 0 || exponent > 65537 {
			return nil, errors.New("invalid Pocket ID RSA key")
		}
		return &rsa.PublicKey{N: modulus, E: exponent}, nil
	}
	return nil, errors.New("no matching Pocket ID signing key")
}

func (p *pocketVerifier) verify(ctx context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
	claims := &pocketClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("token has no kid")
		}
		return p.publicKey(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(p.issuer),
		jwt.WithAudience(p.audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("%w: token rejected", auth.ErrInvalidToken)
	}
	if typ, ok := parsed.Header["typ"].(string); !ok || (typ != "at+jwt" && typ != "application/at+jwt") {
		return nil, fmt.Errorf("%w: not an access token", auth.ErrInvalidToken)
	}
	if claims.Subject != p.allowedSub {
		return nil, fmt.Errorf("%w: user not permitted", auth.ErrInvalidToken)
	}
	var validScopes []string
	for _, scope := range strings.Fields(claims.Scope) {
		if scope == pocketScope || scope == rotateScope {
			validScopes = append(validScopes, scope)
		}
	}
	if len(validScopes) == 0 {
		return nil, fmt.Errorf("%w: missing required scope", auth.ErrInvalidToken)
	}
	return &auth.TokenInfo{UserID: claims.Subject, Scopes: validScopes, Expiration: claims.ExpiresAt.Time}, nil
}

func protectedResourceHandler(resource, issuer string, rotationEnabled bool) http.Handler {
	scopes := []string{pocketScope}
	if rotationEnabled {
		scopes = append(scopes, rotateScope)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":                 resource,
			"authorization_servers":    []string{issuer},
			"scopes_supported":         scopes,
			"bearer_methods_supported": []string{"header"},
		})
	})
}
