package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hybridDecrypt mirrors the controller side, to prove hybridEncrypt's format.
func hybridDecrypt(priv *rsa.PrivateKey, ct, label []byte) ([]byte, error) {
	n := int(binary.BigEndian.Uint16(ct))
	key, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ct[2:2+n], label)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead.Open(nil, make([]byte, aead.NonceSize()), ct[2+n:], nil)
}

func testKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSealStrictRoundTrip(t *testing.T) {
	priv, certPEM := testKey(t)
	pub, err := parseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := sealStrict(pub, secretSpec{
		Namespace: "apps", Name: "db", Type: "Opaque",
		Labels: map[string]string{"app": "db"},
		Data:   map[string][]byte{"PASSWORD": []byte("s3cret"), "user name": []byte("admin")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ss.Kind != "SealedSecret" || ss.Metadata.Namespace != "apps" ||
		ss.Spec.Template.Type != "Opaque" || ss.Spec.Template.Metadata.Labels["app"] != "db" {
		t.Errorf("unexpected resource: %+v", ss)
	}
	if j, _ := json.Marshal(ss); strings.Contains(string(j), "s3cret") {
		t.Fatal("plaintext leaked into output")
	}
	ct, _ := base64.StdEncoding.DecodeString(ss.Spec.EncryptedData["PASSWORD"])
	got, err := hybridDecrypt(priv, ct, []byte("apps/db"))
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	if _, err := hybridDecrypt(priv, ct, []byte("other/db")); err == nil {
		t.Fatal("strict scope not enforced: decrypted with another namespace")
	}
}

func testSigner(t *testing.T, maxTTL time.Duration) *signer {
	t.Helper()
	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := loadSigner(f, "https://seal.example.com/mcp", maxTTL)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTokens(t *testing.T) {
	s := testSigner(t, 24*time.Hour)
	tok, err := s.issue("codex", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ti, err := s.verify(context.Background(), tok, nil)
	if err != nil || ti.UserID != "codex" {
		t.Fatalf("verify = %+v, %v", ti, err)
	}
	if _, err := s.issue("codex", 25*time.Hour); err == nil {
		t.Error("issued a token above the max TTL")
	}
	other := *s
	other.audience = "https://elsewhere/mcp"
	if _, err := other.verify(context.Background(), tok, nil); err == nil {
		t.Error("accepted a token for another audience")
	}
	shorter := *s
	shorter.maxTTL = time.Minute
	if _, err := shorter.verify(context.Background(), tok, nil); err == nil {
		t.Error("accepted a token longer than the current max TTL")
	}
	other = *s
	other.key = []byte(strings.Repeat("x", 32))
	if _, err := other.verify(context.Background(), tok, nil); err == nil {
		t.Error("accepted a token signed with another key")
	}
}

// fakeCluster serves the controller certificate and a single Secret apps/db.
func fakeCluster(t *testing.T) (*tools, *rsa.PrivateKey) {
	t.Helper()
	priv, certPEM := testKey(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/cert.pem", func(w http.ResponseWriter, _ *http.Request) { w.Write(certPEM) })
	mux.HandleFunc("/api/v1/namespaces/apps/secrets/db", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"metadata":{"name":"db","uid":"x","resourceVersion":"9",
			"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}","team":"core"}},
			"type":"Opaque","data":{"PASSWORD":"czNjcmV0"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	k, _ := newKube(srv.URL)
	return &tools{kube: k, certURL: srv.URL + "/v1/cert.pem"}, priv
}

func TestSealExisting(t *testing.T) {
	tl, _ := fakeCluster(t)
	_, out, err := tl.sealExisting(context.Background(), nil, target{Namespace: "apps", Name: "db"})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := out.SealedSecret.Spec.Template.Metadata
	if _, ok := tmpl.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; ok {
		t.Error("live-object metadata leaked into the template")
	}
	if tmpl.Annotations["team"] != "core" || len(out.SealedSecret.Spec.EncryptedData) != 1 || len(out.Notes) != 1 {
		t.Errorf("unexpected output: %+v", out)
	}
	if _, _, err := tl.sealExisting(context.Background(), nil, target{Namespace: "apps", Name: "missing"}); err == nil {
		t.Error("sealed a Secret that does not exist")
	}
	if _, _, err := tl.sealExisting(context.Background(), nil, target{Namespace: "../x", Name: "db"}); err == nil {
		t.Error("accepted an invalid namespace")
	}
}

func TestGenerate(t *testing.T) {
	tl, _ := fakeCluster(t)
	ctx := context.Background()
	in := generateInput{target: target{Namespace: "apps", Name: "new"},
		Keys: []keySpec{{Key: "TOKEN"}, {Key: "PIN", Encoding: "alnum", Length: 20}}}
	_, out, err := tl.generate(ctx, nil, in)
	if err != nil || len(out.SealedSecret.Spec.EncryptedData) != 2 {
		t.Fatalf("generate = %+v, %v", out, err)
	}
	in.target.Name = "db"
	if _, _, err := tl.generate(ctx, nil, in); err == nil {
		t.Error("generate overwrote an existing Secret")
	}
	in.target.Name = "new"
	in.Keys = []keySpec{{Key: "A"}, {Key: "A"}}
	if _, _, err := tl.generate(ctx, nil, in); err == nil {
		t.Error("accepted duplicate keys")
	}
}
