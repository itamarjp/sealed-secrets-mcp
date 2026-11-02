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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const testAudience = "https://seal.example.com/mcp"

func TestParseTargets(t *testing.T) {
	allowed, rotate, err := parseTargets("kingp2p-test", " db , r2,ghcr-pull", "r2")
	if err != nil {
		t.Fatal(err)
	}
	want := []target{{"kingp2p-test", "db"}, {"kingp2p-test", "r2"}, {"kingp2p-test", "ghcr-pull"}}
	if !slices.Equal(allowed, want) || !slices.Equal(rotate, []target{{"kingp2p-test", "r2"}}) {
		t.Errorf("parseTargets = %v, %v", allowed, rotate)
	}
	if _, rotate, _ := parseTargets("ns", "db", ""); rotate != nil {
		t.Errorf("rotation enabled without SEAL_POCKET_ID_ROTATE_TARGET_NAMES: %v", rotate)
	}
	for _, c := range []struct{ ns, names, rotate, want string }{
		{"", "db", "", "invalid Pocket ID target"},
		{"ns", "", "", "invalid Pocket ID target"},
		{"ns", "db,", "", "invalid Pocket ID target"},
		{"ns", "Db", "", "invalid Pocket ID target"},
		{"ns", "db,db", "", "duplicate Pocket ID target"},
		{"ns", "db", "other", "must be a unique read-allowed target"},
		{"ns", "db", "db,db", "must be a unique read-allowed target"},
		{"ns", "db", "DB", "invalid OAuth rotation target"},
	} {
		_, _, err := parseTargets(c.ns, c.names, c.rotate)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("parseTargets(%q, %q, %q) = %v, want %q", c.ns, c.names, c.rotate, err, c.want)
		}
	}
}

// testEnv returns a getenv for newApp backed by a map, with a valid signing
// key file and the given fake cluster.
func testEnv(t *testing.T, kubeURL string, vars map[string]string) func(string) string {
	t.Helper()
	key := filepath.Join(t.TempDir(), "signing-key")
	if err := os.WriteFile(key, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"SEAL_SIGNING_KEY_FILE": key,
		"SEAL_AUDIENCE":         testAudience,
		"SEAL_KUBE_API":         kubeURL,
		"SEAL_CERT_URL":         kubeURL + "/v1/cert.pem",
	}
	for k, v := range vars {
		env[k] = v
	}
	return func(k string) string { return env[k] }
}

func TestNewAppConfigurationErrors(t *testing.T) {
	_, _, kubeURL := clusterWith(t, nil)
	pocket := map[string]string{
		"SEAL_AUTH_MODE":                  "hybrid",
		"SEAL_POCKET_ID_ISSUER":           "https://id.example.com",
		"SEAL_POCKET_ID_SUB":              "alice",
		"SEAL_POCKET_ID_TARGET_NAMESPACE": "apps",
		"SEAL_POCKET_ID_TARGET_NAMES":     "db",
	}
	with := func(over map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range pocket {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	cases := map[string]map[string]string{
		"unknown mode":         {"SEAL_AUTH_MODE": "basic"},
		"bad max ttl":          {"SEAL_MAX_TTL": "forever"},
		"missing key":          {"SEAL_SIGNING_KEY_FILE": "/nonexistent"},
		"missing audience":     {"SEAL_AUDIENCE": ""},
		"http issuer":          with(map[string]string{"SEAL_POCKET_ID_ISSUER": "http://id.example.com"}),
		"no subject":           with(map[string]string{"SEAL_POCKET_ID_SUB": ""}),
		"no targets":           with(map[string]string{"SEAL_POCKET_ID_TARGET_NAMES": ""}),
		"rotate not readable":  with(map[string]string{"SEAL_POCKET_ID_ROTATE_TARGET_NAMES": "other"}),
		"challenge no rotate":  with(map[string]string{"SEAL_POCKET_ID_CHALLENGE_ROTATE": "true"}),
		"challenge bad value":  with(map[string]string{"SEAL_POCKET_ID_CHALLENGE_ROTATE": "1"}),
		"hybrid without key":   with(map[string]string{"SEAL_SIGNING_KEY_FILE": "/nonexistent"}),
		"pocketid bad targets": with(map[string]string{"SEAL_AUTH_MODE": "pocketid", "SEAL_POCKET_ID_TARGET_NAMES": "a,a"}),
	}
	for name, vars := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := newApp(testEnv(t, kubeURL, vars)); err == nil {
				t.Error("newApp accepted an invalid configuration")
			}
		})
	}
	// The legacy single-target variable still configures the allowlist.
	a, err := newApp(testEnv(t, kubeURL, with(map[string]string{"SEAL_POCKET_ID_TARGET_NAMES": "", "SEAL_POCKET_ID_TARGET_NAME": "db"})))
	if err != nil || !slices.Equal(a.tools.allowedTargets, []target{{"apps", "db"}}) {
		t.Fatalf("SEAL_POCKET_ID_TARGET_NAME fallback: %+v, %v", a, err)
	}
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func connect(t *testing.T, url, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: url + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token}}, MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s is not annotated read-only", tool.Name)
		}
	}
	slices.Sort(names)
	return names
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (sealedOutput, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		var msg []string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				msg = append(msg, tc.Text)
			}
		}
		return sealedOutput{}, strings.Join(msg, " ")
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out sealedOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: decoding %s: %v", name, raw, err)
	}
	return out, ""
}

func TestServeJWTMode(t *testing.T) {
	_, priv, kubeURL := clusterWith(t, map[string]string{"apps/db": dbSecret})
	getenv := testEnv(t, kubeURL, nil)
	a, err := newApp(getenv)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.handler)
	defer srv.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %v %v", path, resp.Status, err)
		}
		resp.Body.Close()
	}
	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource")
	if err == nil && resp.StatusCode != http.StatusNotFound {
		t.Errorf("jwt mode serves OAuth metadata: %s", resp.Status)
	}
	resp.Body.Close()

	resp, err = http.Post(srv.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /mcp: %v %v", resp.Status, err)
	}
	if h := resp.Header.Get("WWW-Authenticate"); strings.Contains(h, "scope=") {
		t.Errorf("jwt mode advertises OAuth scope: %q", h)
	}
	resp.Body.Close()

	s, _ := signerFromEnv(getenv)
	tok, err := s.issue("codex", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cs := connect(t, srv.URL, tok)
	if got := toolNames(t, cs); !slices.Equal(got, []string{"generate_sealed_secret", "seal_existing_secret"}) {
		t.Errorf("jwt tools = %v", got)
	}
	out, errMsg := callTool(t, cs, "seal_existing_secret", map[string]any{"namespace": "apps", "name": "db"})
	if errMsg != "" {
		t.Fatal(errMsg)
	}
	if decrypt(t, priv, out, "PASSWORD") != "s3cret" || out.File != "db.sealed.yaml" {
		t.Errorf("seal_existing over MCP: %+v", out)
	}
	if _, errMsg = callTool(t, cs, "generate_sealed_secret", map[string]any{
		"namespace": "apps", "name": "db", "keys": []map[string]any{{"key": "K"}}}); !strings.Contains(errMsg, "already exists") {
		t.Errorf("generate over an existing Secret: %q", errMsg)
	}
	if _, errMsg = callTool(t, cs, "seal_existing_secret", map[string]any{"namespace": "apps", "name": "../db"}); errMsg == "" {
		t.Error("path traversal accepted over MCP")
	}
}

// pocketIssuer is a fake Pocket ID that signs RS256 access tokens.
type pocketIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newPocketIssuer(t *testing.T) *pocketIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return &pocketIssuer{srv: srv, key: key}
}

func (p *pocketIssuer) token(t *testing.T, sub, scope string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, pocketClaims{Scope: scope, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: p.srv.URL, Subject: sub, Audience: jwt.ClaimStrings{testAudience},
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}})
	tok.Header["kid"] = "k1"
	tok.Header["typ"] = "at+jwt"
	raw, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestServeHybridMode(t *testing.T) {
	_, priv, kubeURL := clusterWith(t, map[string]string{"apps/db": dbSecret, "apps/r2": dbSecret, "apps/other": dbSecret})
	issuer := newPocketIssuer(t)
	getenv := testEnv(t, kubeURL, map[string]string{
		"SEAL_AUTH_MODE":                     "hybrid",
		"SEAL_POCKET_ID_ISSUER":              issuer.srv.URL,
		"SEAL_POCKET_ID_SUB":                 "alice",
		"SEAL_POCKET_ID_TARGET_NAMESPACE":    "apps",
		"SEAL_POCKET_ID_TARGET_NAMES":        "db,r2",
		"SEAL_POCKET_ID_ROTATE_TARGET_NAMES": "r2",
	})
	a, err := newApp(getenv)
	if err != nil {
		t.Fatal(err)
	}
	a.pocket.http = issuer.srv.Client() // trust the fake issuer's TLS certificate
	srv := httptest.NewServer(a.handler)
	defer srv.Close()

	// Discovery: metadata advertises rotation, but the challenge still asks
	// for the read scope only (Pocket ID refuses unknown grants).
	const meta = "https://seal.example.com/.well-known/oauth-protected-resource/mcp"
	resp, err := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if want := `Bearer resource_metadata="` + meta + `", scope="seal:existing"`; resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != want {
		t.Errorf("challenge = %d %q, want %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"), want)
	}
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var md struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			ScopesSupported      []string `json:"scopes_supported"`
		}
		json.NewDecoder(resp.Body).Decode(&md)
		resp.Body.Close()
		if md.Resource != testAudience || !slices.Equal(md.AuthorizationServers, []string{issuer.srv.URL}) ||
			!slices.Contains(md.ScopesSupported, rotateScope) {
			t.Errorf("%s: metadata %+v", path, md)
		}
	}

	// Legacy JWT: all non-rotation tools, any RBAC-readable target, no rotation.
	s, _ := signerFromEnv(getenv)
	legacyTok, _ := s.issue("codex", time.Hour)
	legacy := connect(t, srv.URL, legacyTok)
	all := []string{"generate_sealed_secret", "rotate_sealed_secret", "seal_existing_secret"}
	if got := toolNames(t, legacy); !slices.Equal(got, all) {
		t.Errorf("hybrid tools = %v", got)
	}
	if _, errMsg := callTool(t, legacy, "seal_existing_secret", map[string]any{"namespace": "apps", "name": "other"}); errMsg != "" {
		t.Errorf("legacy seal_existing: %s", errMsg)
	}
	if _, errMsg := callTool(t, legacy, "rotate_sealed_secret", map[string]any{
		"namespace": "apps", "name": "r2", "keys": []map[string]any{{"key": "PASSWORD"}}}); !strings.Contains(errMsg, "seal:rotate") {
		t.Errorf("legacy JWT rotated: %q", errMsg)
	}

	// OAuth with the read scope: allowlisted targets only, no generate/rotate.
	reader := connect(t, srv.URL, issuer.token(t, "alice", pocketScope))
	if _, errMsg := callTool(t, reader, "seal_existing_secret", map[string]any{"namespace": "apps", "name": "db"}); errMsg != "" {
		t.Errorf("OAuth seal_existing: %s", errMsg)
	}
	if _, errMsg := callTool(t, reader, "seal_existing_secret", map[string]any{"namespace": "apps", "name": "other"}); !strings.Contains(errMsg, "not permitted") {
		t.Errorf("OAuth read outside allowlist: %q", errMsg)
	}
	if _, errMsg := callTool(t, reader, "generate_sealed_secret", map[string]any{
		"namespace": "apps", "name": "new", "keys": []map[string]any{{"key": "K"}}}); !strings.Contains(errMsg, "not permitted for OAuth") {
		t.Errorf("OAuth generate: %q", errMsg)
	}
	if _, errMsg := callTool(t, reader, "rotate_sealed_secret", map[string]any{
		"namespace": "apps", "name": "r2", "keys": []map[string]any{{"key": "PASSWORD"}}}); !strings.Contains(errMsg, "seal:rotate") {
		t.Errorf("OAuth rotate without scope: %q", errMsg)
	}

	// OAuth with both scopes rotates only the rotation allowlist.
	rotator := connect(t, srv.URL, issuer.token(t, "alice", pocketScope+" "+rotateScope))
	out, errMsg := callTool(t, rotator, "rotate_sealed_secret", map[string]any{
		"namespace": "apps", "name": "r2", "keys": []map[string]any{{"key": "PASSWORD", "encoding": "alnum", "length": 40}}})
	if errMsg != "" {
		t.Fatal(errMsg)
	}
	if v := decrypt(t, priv, out, "PASSWORD"); len(v) != 40 || v == "s3cret" {
		t.Errorf("rotated PASSWORD = %q", v)
	}
	if _, errMsg := callTool(t, rotator, "rotate_sealed_secret", map[string]any{
		"namespace": "apps", "name": "db", "keys": []map[string]any{{"key": "PASSWORD"}}}); !strings.Contains(errMsg, "not permitted for OAuth rotation") {
		t.Errorf("rotated a read-only target: %q", errMsg)
	}

	// Another Pocket ID user is rejected at the HTTP layer.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+issuer.token(t, "mallory", pocketScope))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), `Bearer error="invalid_token"`) {
		t.Errorf("other subject: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func TestServePocketIDMode(t *testing.T) {
	_, _, kubeURL := clusterWith(t, map[string]string{"apps/db": dbSecret})
	issuer := newPocketIssuer(t)
	a, err := newApp(testEnv(t, kubeURL, map[string]string{
		"SEAL_AUTH_MODE":                  "pocketid",
		"SEAL_POCKET_ID_ISSUER":           issuer.srv.URL,
		"SEAL_POCKET_ID_SUB":              "alice",
		"SEAL_POCKET_ID_TARGET_NAMESPACE": "apps",
		"SEAL_POCKET_ID_TARGET_NAMES":     "db",
	}))
	if err != nil {
		t.Fatal(err)
	}
	a.pocket.http = issuer.srv.Client()
	srv := httptest.NewServer(a.handler)
	defer srv.Close()

	cs := connect(t, srv.URL, issuer.token(t, "alice", pocketScope))
	if got := toolNames(t, cs); !slices.Equal(got, []string{"seal_existing_secret"}) {
		t.Errorf("pocketid tools = %v (generate and rotate must be absent)", got)
	}
	if _, errMsg := callTool(t, cs, "seal_existing_secret", map[string]any{"namespace": "apps", "name": "db"}); errMsg != "" {
		t.Error(errMsg)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	_, _, kubeURL := clusterWith(t, nil)
	getenv := testEnv(t, kubeURL, nil)
	a, err := newApp(getenv)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.handler)
	defer srv.Close()
	s, _ := signerFromEnv(getenv)
	tok, _ := s.issue("codex", time.Hour)
	body := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", 2<<20) + `"}}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Errorf("2 MiB request accepted with %s; the 1 MiB limit is not enforced", resp.Status)
	}
}
