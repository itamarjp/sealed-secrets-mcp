package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// withIdentity returns a context carrying info exactly as the SDK's bearer
// middleware stores it, so tool handlers see a real authenticated request.
func withIdentity(t *testing.T, userID string, scopes ...string) context.Context {
	t.Helper()
	info := &auth.TokenInfo{UserID: userID, Scopes: scopes, Expiration: time.Now().Add(time.Hour)}
	var ctx context.Context
	h := auth.RequireBearerToken(func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return info, nil
	}, nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() }))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer x")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if ctx == nil {
		t.Fatal("bearer middleware did not call the handler")
	}
	return ctx
}

// clusterWith serves the controller certificate and the given Secrets, keyed
// by "namespace/name" with the raw JSON body the API server would return.
func clusterWith(t *testing.T, secrets map[string]string) (*tools, *rsa.PrivateKey, string) {
	t.Helper()
	priv, certPEM := testKey(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/cert.pem", func(w http.ResponseWriter, _ *http.Request) { w.Write(certPEM) })
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"gitVersion":"v1.37.0"}`)) })
	mux.HandleFunc("/api/v1/namespaces/{ns}/secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("kube client sent %s; it must be read-only", r.Method)
		}
		body, ok := secrets[r.PathValue("ns")+"/"+r.PathValue("name")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	k, err := newKube(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &tools{kube: k, certURL: srv.URL + "/v1/cert.pem"}, priv, srv.URL
}

const dbSecret = `{"metadata":{"name":"db","labels":{"app":"db"},
	"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}","sealedsecrets.bitnami.com/managed":"true","team":"core"}},
	"type":"Opaque","data":{"PASSWORD":"czNjcmV0","USER":"YWRtaW4="}}`

func decrypt(t *testing.T, priv *rsa.PrivateKey, out sealedOutput, key string) string {
	t.Helper()
	ct, err := base64.StdEncoding.DecodeString(out.SealedSecret.Spec.EncryptedData[key])
	if err != nil {
		t.Fatal(err)
	}
	m := out.SealedSecret.Metadata
	pt, err := hybridDecrypt(priv, ct, []byte(m.Namespace+"/"+m.Name))
	if err != nil {
		t.Fatalf("decrypt %s: %v", key, err)
	}
	return string(pt)
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("error = %v, want one containing %q", err, contains)
	}
}

func TestRotateReplacesOnlyNamedKeys(t *testing.T) {
	tl, priv, _ := clusterWith(t, map[string]string{"apps/db": dbSecret})
	tl.hybrid = true
	tl.allowedTargets = []target{{Namespace: "apps", Name: "db"}}
	tl.rotateTargets = tl.allowedTargets
	ctx := withIdentity(t, "pocketid:alice", pocketScope, rotateScope)

	_, out, err := tl.rotate(ctx, nil, rotateInput{target: tl.rotateTargets[0],
		Keys: []keySpec{{Key: "PASSWORD", Length: 24}}})
	if err != nil {
		t.Fatal(err)
	}
	got := decrypt(t, priv, out, "PASSWORD")
	if got == "s3cret" || !regexp.MustCompile(`^[0-9a-f]{48}$`).MatchString(got) {
		t.Errorf("PASSWORD not rotated to 24 random hex bytes: %q", got)
	}
	if user := decrypt(t, priv, out, "USER"); user != "admin" {
		t.Errorf("unrotated key changed: USER=%q", user)
	}
	tmpl := out.SealedSecret.Spec.Template
	if tmpl.Type != "Opaque" || tmpl.Metadata.Labels["app"] != "db" || tmpl.Metadata.Annotations["team"] != "core" {
		t.Errorf("metadata not preserved: %+v", tmpl)
	}
	for k := range tmpl.Metadata.Annotations {
		if strings.HasPrefix(k, "sealedsecrets.bitnami.com/") || strings.HasPrefix(k, "kubectl.kubernetes.io/") {
			t.Errorf("live-object annotation %q copied into template", k)
		}
	}
	if len(out.Notes) != 1 || !strings.Contains(out.Notes[0], "NOT applied") {
		t.Errorf("missing GitOps note: %q", out.Notes)
	}
}

func TestRotateRefusals(t *testing.T) {
	sa := `{"metadata":{"name":"sa"},"type":"kubernetes.io/service-account-token","data":{"token":"eA=="}}`
	tl, _, _ := clusterWith(t, map[string]string{"apps/db": dbSecret, "apps/sa": sa})
	tl.hybrid = true
	tl.allowedTargets = []target{{Namespace: "apps", Name: "db"}, {Namespace: "apps", Name: "sa"},
		{Namespace: "apps", Name: "gone"}, {Namespace: "apps", Name: "readonly"}}
	tl.rotateTargets = tl.allowedTargets[:3]
	rotator := withIdentity(t, "pocketid:alice", pocketScope, rotateScope)
	db := target{Namespace: "apps", Name: "db"}
	pw := []keySpec{{Key: "PASSWORD"}}

	cases := []struct {
		name string
		ctx  context.Context
		in   rotateInput
		want string
	}{
		{"no identity", context.Background(), rotateInput{db, pw}, "seal:rotate scope is required"},
		{"read scope only", withIdentity(t, "pocketid:alice", pocketScope), rotateInput{db, pw}, "seal:rotate scope is required"},
		{"legacy jwt", withIdentity(t, "jwt:codex", rotateScope), rotateInput{db, pw}, "seal:rotate scope is required"},
		{"invalid name", rotator, rotateInput{target{"apps", "DB"}, pw}, "valid Kubernetes names"},
		{"read-only target", rotator, rotateInput{target{"apps", "readonly"}, pw}, "not permitted for OAuth rotation"},
		{"unlisted target", rotator, rotateInput{target{"other", "db"}, pw}, "not permitted for OAuth rotation"},
		{"no keys", rotator, rotateInput{db, nil}, "at least one existing key"},
		{"missing secret", rotator, rotateInput{target{"apps", "gone"}, pw}, "requires existing Secret"},
		{"service account token", rotator, rotateInput{target{"apps", "sa"}, []keySpec{{Key: "token"}}}, "cannot be rotated"},
		{"new key", rotator, rotateInput{db, []keySpec{{Key: "NEW"}}}, "does not exist in Secret"},
		{"duplicate key", rotator, rotateInput{db, []keySpec{{Key: "PASSWORD"}, {Key: "PASSWORD"}}}, "invalid or duplicate"},
		{"bad key", rotator, rotateInput{db, []keySpec{{Key: "a/b"}}}, "invalid or duplicate"},
		{"short value", rotator, rotateInput{db, []keySpec{{Key: "PASSWORD", Length: 8}}}, "between 16 and 256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := tl.rotate(c.ctx, nil, c.in)
			wantErr(t, err, c.want)
		})
	}
}

func TestSealExistingHybridAuthorization(t *testing.T) {
	tl, priv, _ := clusterWith(t, map[string]string{"apps/db": dbSecret, "apps/other": dbSecret})
	tl.hybrid = true
	tl.allowedTargets = []target{{Namespace: "apps", Name: "db"}}
	db := target{Namespace: "apps", Name: "db"}
	other := target{Namespace: "apps", Name: "other"}

	// Legacy JWTs are limited by RBAC only, not by the OAuth allowlist.
	_, out, err := tl.sealExisting(withIdentity(t, "jwt:codex"), nil, other)
	if err != nil {
		t.Fatalf("legacy client refused: %v", err)
	}
	if decrypt(t, priv, out, "PASSWORD") != "s3cret" {
		t.Error("seal_existing changed the value")
	}
	if _, _, err := tl.sealExisting(withIdentity(t, "pocketid:alice", pocketScope), nil, db); err != nil {
		t.Fatalf("OAuth client refused on allowed target: %v", err)
	}

	cases := []struct {
		name string
		ctx  context.Context
		in   target
		want string
	}{
		{"oauth without scope", withIdentity(t, "pocketid:alice"), db, "seal:existing scope is required"},
		{"oauth with rotate only", withIdentity(t, "pocketid:alice", rotateScope), db, "seal:existing scope is required"},
		{"oauth outside allowlist", withIdentity(t, "pocketid:alice", pocketScope), other, "not permitted"},
		{"unprefixed identity", withIdentity(t, "codex", pocketScope), db, "unauthorized client identity"},
		{"no identity", context.Background(), db, "unauthorized client identity"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := tl.sealExisting(c.ctx, nil, c.in)
			wantErr(t, err, c.want)
		})
	}
}

func TestSealExistingPocketOnlyRequiresScope(t *testing.T) {
	tl, _, _ := clusterWith(t, map[string]string{"apps/db": dbSecret})
	tl.allowedTargets = []target{{Namespace: "apps", Name: "db"}}
	db := tl.allowedTargets[0]
	if _, _, err := tl.sealExisting(withIdentity(t, "alice"), nil, db); err == nil {
		t.Error("pocketid mode accepted a token without seal:existing")
	}
	if _, _, err := tl.sealExisting(withIdentity(t, "alice", pocketScope), nil, db); err != nil {
		t.Errorf("pocketid mode refused a scoped token: %v", err)
	}
}

func TestSealExistingNotes(t *testing.T) {
	unmanaged := `{"metadata":{"name":"plain"},"type":"Opaque","data":{"K":"dg=="}}`
	owned := `{"metadata":{"name":"owned","ownerReferences":[{"kind":"SealedSecret","name":"owned"}]},"type":"Opaque","data":{"K":"dg=="}}`
	foreign := `{"metadata":{"name":"cert","ownerReferences":[{"kind":"Certificate","name":"web"}]},"type":"kubernetes.io/tls","data":{"tls.crt":"dg=="}}`
	sa := `{"metadata":{"name":"sa"},"type":"kubernetes.io/service-account-token","data":{"token":"dg=="}}`
	tl, _, _ := clusterWith(t, map[string]string{"apps/db": dbSecret, "apps/plain": unmanaged,
		"apps/owned": owned, "apps/cert": foreign, "apps/sa": sa})
	ctx := context.Background()

	notes := func(name string) []string {
		t.Helper()
		_, out, err := tl.sealExisting(ctx, nil, target{Namespace: "apps", Name: name})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return out.Notes
	}
	if n := notes("db"); len(n) != 0 {
		t.Errorf("managed Secret got notes: %q", n)
	}
	if n := notes("plain"); len(n) != 1 || !strings.Contains(n[0], "kubectl -n apps annotate secret plain sealedsecrets.bitnami.com/managed=true") {
		t.Errorf("unmanaged Secret missing annotate hint: %q", n)
	}
	if n := notes("owned"); len(n) != 1 || !strings.Contains(n[0], "already owned by SealedSecret owned") {
		t.Errorf("SealedSecret-owned notes: %q", n)
	}
	if n := notes("cert"); len(n) != 2 || !strings.Contains(n[0], "owned by Certificate web") {
		t.Errorf("foreign-owned notes: %q", n)
	}
	_, _, err := tl.sealExisting(ctx, nil, target{Namespace: "apps", Name: "sa"})
	wantErr(t, err, "service account tokens")
	_, _, err = tl.sealExisting(ctx, nil, target{Namespace: "apps", Name: "missing"})
	wantErr(t, err, "use generate_sealed_secret")
}

func TestGenerateAuthorizationAndValidation(t *testing.T) {
	tl, priv, _ := clusterWith(t, map[string]string{"apps/db": dbSecret})
	tl.hybrid = true
	fresh := target{Namespace: "apps", Name: "fresh"}

	_, _, err := tl.generate(withIdentity(t, "pocketid:alice", pocketScope, rotateScope), nil,
		generateInput{target: fresh, Keys: []keySpec{{Key: "K"}}})
	wantErr(t, err, "not permitted for OAuth clients")
	_, _, err = tl.generate(context.Background(), nil, generateInput{target: fresh, Keys: []keySpec{{Key: "K"}}})
	wantErr(t, err, "not permitted for OAuth clients")

	jwtCtx := withIdentity(t, "jwt:codex")
	_, out, err := tl.generate(jwtCtx, nil, generateInput{target: fresh, Type: "kubernetes.io/basic-auth",
		Keys: []keySpec{{Key: "password", Encoding: "base64url", Length: 18}}})
	if err != nil {
		t.Fatal(err)
	}
	if out.SealedSecret.Spec.Template.Type != "kubernetes.io/basic-auth" || out.File != "fresh.sealed.yaml" {
		t.Errorf("unexpected output: %+v", out)
	}
	if v := decrypt(t, priv, out, "password"); len(v) != 24 {
		t.Errorf("base64url of 18 bytes should be 24 chars, got %q", v)
	}

	for name, in := range map[string]generateInput{
		"no keys":     {target: fresh},
		"invalid key": {target: fresh, Keys: []keySpec{{Key: "a b"}}},
		"bad target":  {target: target{Namespace: "", Name: "x"}, Keys: []keySpec{{Key: "K"}}},
		"exists":      {target: target{Namespace: "apps", Name: "db"}, Keys: []keySpec{{Key: "K"}}},
		"encoding":    {target: fresh, Keys: []keySpec{{Key: "K", Encoding: "rot13"}}},
	} {
		if _, _, err := tl.generate(jwtCtx, nil, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenerateRefusesWhenExistenceUnknown(t *testing.T) {
	tl, _, _ := clusterWith(t, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	tl.kube, _ = newKube(srv.URL)
	_, _, err := tl.generate(context.Background(), nil, generateInput{target: target{Namespace: "apps", Name: "x"},
		Keys: []keySpec{{Key: "K"}}})
	wantErr(t, err, "cannot confirm the Secret is new")
}

func TestRandomValueStandardBase64DecodesStrictly(t *testing.T) {
	v, err := randomValue(keySpec{Key: "KEY", Encoding: "base64", Length: 32})
	if err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(string(v))
	if err != nil || len(b) != 32 {
		t.Fatalf("standard base64 value does not decode to 32 bytes (len %d, err %v)", len(b), err)
	}
}

func TestRandomValue(t *testing.T) {
	cases := []struct {
		spec    keySpec
		pattern string
	}{
		{keySpec{Key: "a"}, `^[0-9a-f]{64}$`},
		{keySpec{Key: "a", Encoding: "hex", Length: 16}, `^[0-9a-f]{32}$`},
		{keySpec{Key: "a", Encoding: "base64", Length: 32}, `^[A-Za-z0-9+/]{43}=$`},
		{keySpec{Key: "a", Encoding: "base64", Length: 30}, `^[A-Za-z0-9+/]{40}$`},
		{keySpec{Key: "a", Encoding: "base64url", Length: 30}, `^[A-Za-z0-9_-]{40}$`},
		{keySpec{Key: "a", Encoding: "alnum", Length: 256}, `^[A-Za-z0-9]{256}$`},
	}
	for _, c := range cases {
		v, err := randomValue(c.spec)
		if err != nil {
			t.Fatalf("%+v: %v", c.spec, err)
		}
		if !regexp.MustCompile(c.pattern).Match(v) {
			t.Errorf("%+v: %q does not match %s", c.spec, v, c.pattern)
		}
		w, _ := randomValue(c.spec)
		if string(v) == string(w) {
			t.Errorf("%+v: two calls returned the same value", c.spec)
		}
	}
	for _, bad := range []keySpec{{Key: "a", Length: 15}, {Key: "a", Length: 257}, {Key: "a", Length: -1}, {Key: "a", Encoding: "HEX"}} {
		if _, err := randomValue(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"a", "db", "kingp2p-test", "a.b", "0abc", strings.Repeat("a", 253)} {
		if !validName(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", "DB", "-a", "a-", "a..b", "../x", "a/b", "a_b", " a", strings.Repeat("a", 254)} {
		if validName(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSecretKeyPattern(t *testing.T) {
	for _, ok := range []string{"PASSWORD", "tls.crt", ".dockerconfigjson", "a-b_c"} {
		if !secretKey.MatchString(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", "a b", "a/b", "ä", strings.Repeat("k", 254)} {
		if secretKey.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCleanAnnotations(t *testing.T) {
	got := cleanAnnotations(map[string]string{
		"kubectl.kubernetes.io/last-applied-configuration": "{}",
		"sealedsecrets.bitnami.com/managed":                "true",
		"sealedsecrets.bitnami.com/cluster-wide":           "true",
		"team":                                             "core",
	})
	if len(got) != 1 || got["team"] != "core" {
		t.Errorf("cleanAnnotations = %v", got)
	}
	if got := cleanAnnotations(nil); got == nil || len(got) != 0 {
		t.Errorf("cleanAnnotations(nil) = %v", got)
	}
}

func TestKubeGetSecret(t *testing.T) {
	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/namespaces/apps/secrets/ok", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"type":"Opaque","data":{"K":"dg=="}}`))
	})
	mux.HandleFunc("/api/v1/namespaces/apps/secrets/forbidden", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/api/v1/namespaces/apps/secrets/broken", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/v1/namespaces/apps/secrets/garbage", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &kube{base: srv.URL, tokenFile: tokenFile, http: srv.Client()}
	ctx := context.Background()
	s, err := k.getSecret(ctx, "apps", "ok")
	if err != nil || string(s.Data["K"]) != "v" {
		t.Fatalf("getSecret = %+v, %v", s, err)
	}
	if gotAuth != "Bearer sa-token" {
		t.Errorf("Authorization = %q; the projected token must be sent trimmed", gotAuth)
	}
	_, err = k.getSecret(ctx, "apps", "missing")
	if err != errNotFound {
		t.Errorf("404 = %v, want errNotFound", err)
	}
	_, err = k.getSecret(ctx, "apps", "forbidden")
	wantErr(t, err, "RBAC does not allow reading secret apps/forbidden")
	_, err = k.getSecret(ctx, "apps", "broken")
	wantErr(t, err, "500")
	if _, err = k.getSecret(ctx, "apps", "garbage"); err == nil {
		t.Error("decoded a non-JSON body")
	}
	k.tokenFile = filepath.Join(t.TempDir(), "absent")
	if _, err = k.getSecret(ctx, "apps", "ok"); err == nil {
		t.Error("ignored an unreadable token file")
	}
}

func TestNewKubeOutsideCluster(t *testing.T) {
	if _, err := os.Stat(saDir); err == nil {
		t.Skip("running inside a cluster")
	}
	if _, err := newKube(""); err == nil {
		t.Error("expected an error without SEAL_KUBE_API outside a cluster")
	}
	k, err := newKube("http://127.0.0.1:8001/")
	if err != nil || k.base != "http://127.0.0.1:8001" || k.tokenFile != "" {
		t.Errorf("newKube = %+v, %v", k, err)
	}
}

func TestSealCertificateErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/missing", http.NotFound)
	mux.HandleFunc("/garbage", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("nope")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	spec := secretSpec{Namespace: "apps", Name: "db", Type: "Opaque", Data: map[string][]byte{"K": []byte("v")}}
	for _, path := range []string{"/missing", "/garbage"} {
		tl := &tools{certURL: srv.URL + path}
		if _, err := tl.seal(context.Background(), spec); err == nil {
			t.Errorf("%s: sealed without a valid certificate", path)
		}
	}
}

func TestSignerConfiguration(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("  tooshort  \n"), 0o600)
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte(hex.EncodeToString(make([]byte, 16))+"\n"), 0o600)

	if _, err := loadSigner(filepath.Join(dir, "absent"), "https://a/mcp", time.Hour); err == nil {
		t.Error("loaded a missing key file")
	}
	if _, err := loadSigner(short, "https://a/mcp", time.Hour); err == nil {
		t.Error("accepted a short key")
	}
	if _, err := loadSigner(good, "", time.Hour); err == nil {
		t.Error("accepted an empty audience")
	}
	s, err := loadSigner(good, "https://a/mcp", time.Hour)
	if err != nil || len(s.key) != 32 {
		t.Fatalf("loadSigner = %+v, %v (key must be trimmed)", s, err)
	}
	for _, bad := range []string{"", "Codex", "a/b"} {
		if _, err := s.issue(bad, time.Minute); err == nil {
			t.Errorf("issued a token for client %q", bad)
		}
	}
	if _, err := s.issue("codex", 0); err == nil {
		t.Error("issued a token with zero TTL")
	}
	if got := clientFrom(context.Background()); got != "unknown" {
		t.Errorf("clientFrom(no token) = %q", got)
	}
}
