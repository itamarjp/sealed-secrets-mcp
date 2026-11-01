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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestHybridVerifierKeepsIdentitiesSeparate(t *testing.T) {
	legacy := testSigner(t, 24*time.Hour)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "pocket", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer issuer.Close()
	pocket := &pocketVerifier{issuer: issuer.URL, audience: legacy.audience, allowedSub: "alice", http: issuer.Client()}
	hybrid := &hybridVerifier{legacy: legacy, pocket: pocket}
	oldToken, err := legacy.issue("codex", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := hybrid.verify(context.Background(), oldToken, nil)
	if err != nil || info.UserID != "jwt:codex" {
		t.Fatalf("legacy: %+v, %v", info, err)
	}

	oauth := jwt.NewWithClaims(jwt.SigningMethodRS256, pocketClaims{
		Scope: pocketScope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: issuer.URL, Subject: "alice", Audience: jwt.ClaimStrings{legacy.audience},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	oauth.Header["kid"] = "pocket"
	oauth.Header["typ"] = "at+jwt"
	oauthToken, err := oauth.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	info, err = hybrid.verify(context.Background(), oauthToken, nil)
	if err != nil || info.UserID != "pocketid:alice" {
		t.Fatalf("pocket: %+v, %v", info, err)
	}
	for _, raw := range []string{"garbage", "a.b.c", oldToken + "invalid"} {
		if _, err := hybrid.verify(context.Background(), raw, nil); err == nil {
			t.Error("accepted malformed token")
		}
	}
}
