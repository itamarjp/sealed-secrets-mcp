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
	rotateToken := sign("alice", p.audience, rotateScope, "at+jwt", time.Now().Add(time.Hour))
	rotated, err := p.verify(context.Background(), rotateToken, nil)
	if err != nil || len(rotated.Scopes) != 1 || rotated.Scopes[0] != rotateScope {
		t.Fatalf("rotate scope was not retained: %+v, %v", rotated, err)
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
	if !strings.Contains(w.Body.String(), rotateScope) {
		t.Fatal("rotation scope not advertised when enabled")
	}
}

// TestPocketVerifierKeysAndDiscovery covers the issue #4 cases around the
// issuer and its signing keys: wrong issuer, key rotation (JWKS is read on
// every request, so a new key works at once and a removed key stops
// working), unknown or missing kid, weak keys, and an unreachable or broken
// JWKS endpoint. Every failure must reject the token (fail closed).
func TestPocketVerifierKeysAndDiscovery(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	weakKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	jwk := func(kid string, k *rsa.PrivateKey) map[string]string {
		return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes())}
	}
	var status int
	var body string
	setKeys := func(keys ...map[string]string) {
		b, _ := json.Marshal(map[string]any{"keys": keys})
		status, body = http.StatusOK, string(b)
	}
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer issuer.Close()
	p := &pocketVerifier{issuer: issuer.URL, audience: "https://seal.example.com/mcp", allowedSub: "alice", http: issuer.Client()}

	sign := func(key *rsa.PrivateKey, kid any, iss string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, pocketClaims{Scope: pocketScope, RegisteredClaims: jwt.RegisteredClaims{
			Issuer: iss, Subject: "alice", Audience: jwt.ClaimStrings{p.audience},
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}})
		if kid != nil {
			tok.Header["kid"] = kid
		}
		tok.Header["typ"] = "at+jwt"
		raw, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	accept := func(name, raw string) {
		t.Helper()
		if _, err := p.verify(context.Background(), raw, nil); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
	reject := func(name, raw string) {
		t.Helper()
		if _, err := p.verify(context.Background(), raw, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	setKeys(jwk("old", oldKey))
	accept("current key", sign(oldKey, "old", issuer.URL))
	reject("wrong issuer", sign(oldKey, "old", "https://evil.example.com"))
	reject("issuer with trailing slash", sign(oldKey, "old", issuer.URL+"/"))
	reject("unknown kid", sign(oldKey, "other", issuer.URL))
	reject("missing kid", sign(oldKey, nil, issuer.URL))
	reject("non-string kid", sign(oldKey, 7, issuer.URL))
	reject("kid of another key", sign(newKey, "old", issuer.URL))

	// Rotation: Pocket ID publishes both keys, then drops the old one.
	setKeys(jwk("old", oldKey), jwk("new", newKey))
	accept("new key during overlap", sign(newKey, "new", issuer.URL))
	accept("old key during overlap", sign(oldKey, "old", issuer.URL))
	setKeys(jwk("new", newKey))
	reject("old key after removal", sign(oldKey, "old", issuer.URL))
	accept("new key after removal", sign(newKey, "new", issuer.URL))

	enc := jwk("enc", newKey)
	enc["use"] = "enc"
	ps := jwk("ps", newKey)
	ps["alg"] = "PS256"
	setKeys(enc, ps, jwk("weak", weakKey))
	reject("encryption key", sign(newKey, "enc", issuer.URL))
	reject("key for another algorithm", sign(newKey, "ps", issuer.URL))
	reject("1024-bit key", sign(weakKey, "weak", issuer.URL))

	raw := sign(newKey, "new", issuer.URL)
	for name, resp := range map[string]struct {
		status int
		body   string
	}{
		"JWKS 500":       {http.StatusInternalServerError, ""},
		"JWKS 404":       {http.StatusNotFound, ""},
		"JWKS not JSON":  {http.StatusOK, "<html>"},
		"JWKS no keys":   {http.StatusOK, `{"keys":[]}`},
		"JWKS bad n/e":   {http.StatusOK, `{"keys":[{"kty":"RSA","kid":"new","n":"!!","e":"AQAB"}]}`},
		"JWKS too large": {http.StatusOK, `{"keys":[{"kty":"RSA","kid":"new","n":"` + strings.Repeat("A", 70000) + `","e":"AQAB"}]}`},
	} {
		status, body = resp.status, resp.body
		reject(name, raw)
	}

	issuer.Close()
	reject("issuer unreachable", raw)

	// A token signed with the legacy HMAC method must never pass the RS256 path.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Issuer: p.issuer, Subject: "alice",
		Audience: jwt.ClaimStrings{p.audience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
	hsRaw, _ := hs.SignedString([]byte(strings.Repeat("k", 32)))
	reject("HS256 token", hsRaw)
}
