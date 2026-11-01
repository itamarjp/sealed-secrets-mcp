package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestPocketVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer issuer.Close()
	p := &pocketVerifier{issuer: issuer.URL, audience: "https://seal.example.com/mcp", allowedSub: "alice", http: issuer.Client()}
	sign := func(sub, aud, scope, typ string, exp time.Time) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, pocketClaims{
			Scope: scope, RegisteredClaims: jwt.RegisteredClaims{
				Issuer: issuer.URL, Subject: sub, Audience: jwt.ClaimStrings{aud},
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				ExpiresAt: jwt.NewNumericDate(exp),
			},
		})
		tok.Header["kid"] = "test"
		tok.Header["typ"] = typ
		raw, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	valid := sign("alice", p.audience, pocketScope, "at+jwt", time.Now().Add(time.Hour))
	got, err := p.verify(context.Background(), valid, nil)
	if err != nil || got.UserID != "alice" {
		t.Fatalf("valid token: %+v, %v", got, err)
	}
	cases := map[string]string{
		"wrong user":     sign("bob", p.audience, pocketScope, "at+jwt", time.Now().Add(time.Hour)),
		"wrong audience": sign("alice", "https://other.example.com", pocketScope, "at+jwt", time.Now().Add(time.Hour)),
		"wrong scope":    sign("alice", p.audience, "openid", "at+jwt", time.Now().Add(time.Hour)),
		"id token":       sign("alice", p.audience, pocketScope, "JWT", time.Now().Add(time.Hour)),
		"expired":        sign("alice", p.audience, pocketScope, "at+jwt", time.Now().Add(-time.Minute)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := p.verify(context.Background(), raw, nil); err == nil {
				t.Error("accepted invalid access token")
			}
		})
	}
}

func TestPocketConfiguration(t *testing.T) {
	_, err := newPocketVerifier("https://id.example.com", "https://seal.example.com/mcp", "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []string{"http://id.example.com", "https://id.example.com/redirect", "https://user:pass@id.example.com"} {
		if _, err := newPocketVerifier(issuer, "https://seal.example.com/mcp", "alice"); err == nil {
			t.Error("accepted issuer", issuer)
		}
	}
	if _, err := newPocketVerifier("https://id.example.com", "https://seal.example.com/mcp", ""); err == nil {
		t.Error("accepted missing allowed subject")
	}
	h := protectedResourceHandler("https://seal.example.com/mcp", "https://id.example.com", false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), pocketScope) {
		t.Fatalf("bad metadata %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	protectedResourceHandler("https://seal.example.com/mcp", "https://id.example.com", true).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(w.Body.String(), rotateScope) { t.Fatal("rotation scope not advertised when enabled") }
}
