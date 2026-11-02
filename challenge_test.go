package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestOAuthChallengeAdvertisesReadScope(t *testing.T) {
	const meta = "https://seal.example.com/.well-known/oauth-protected-resource/mcp"
	verify := func(_ context.Context, tok string, _ *http.Request) (*auth.TokenInfo, error) {
		if tok == "good" {
			// Legacy HS256 clients carry no scopes; they must still pass.
			return &auth.TokenInfo{UserID: "jwt:codex", Expiration: time.Now().Add(time.Hour)}, nil
		}
		return nil, auth.ErrInvalidToken
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			t.Error("response writer lost http.Flusher")
		}
		w.Write([]byte("ok"))
	})
	h := oauthChallenge(meta, pocketScope)(auth.RequireBearerToken(verify,
		&auth.RequireBearerTokenOptions{ResourceMetadataURL: meta})(inner))

	cases := []struct {
		authz, want string
		code        int
	}{
		{"", `Bearer resource_metadata="` + meta + `", scope="seal:existing"`, 401},
		{"Bearer bad", `Bearer error="invalid_token", resource_metadata="` + meta + `", scope="seal:existing"`, 401},
		{"Bearer good", "", 200},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if c.authz != "" {
			req.Header.Set("Authorization", c.authz)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Errorf("%q: status %d, want %d", c.authz, rec.Code, c.code)
		}
		got := rec.Header().Values("WWW-Authenticate")
		if c.want == "" && len(got) != 0 || c.want != "" && (len(got) != 1 || got[0] != c.want) {
			t.Errorf("%q: WWW-Authenticate %q, want %q", c.authz, got, c.want)
		}
	}
}

func TestChallengeScope(t *testing.T) {
	cases := []struct {
		rotation bool
		optIn    string
		want     string
		wantErr  bool
	}{
		{false, "", "seal:existing", false},
		{true, "", "seal:existing", false},
		{true, "false", "seal:existing", false},
		{true, "true", "seal:existing seal:rotate", false},
		{false, "true", "", true},
		{true, "yes", "", true},
	}
	for _, c := range cases {
		got, err := challengeScope(c.rotation, c.optIn)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("challengeScope(%v, %q) = %q, %v; want %q, err=%v", c.rotation, c.optIn, got, err, c.want, c.wantErr)
		}
	}
}
