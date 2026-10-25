package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestKubesealCompat decrypts our output with the official kubeseal binary.
// It runs when kubeseal is on PATH (CI installs it).
func TestKubesealCompat(t *testing.T) {
	bin, err := exec.LookPath("kubeseal")
	if err != nil {
		t.Skip("kubeseal not on PATH")
	}
	priv, certPEM := testKey(t)
	pub, _ := parseCert(certPEM)
	ss, err := sealStrict(pub, secretSpec{Namespace: "apps", Name: "db", Type: "Opaque",
		Data: map[string][]byte{"PASSWORD": []byte("s3cret")}})
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(ss) // kubeseal reads JSON as well as YAML
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--recovery-unseal", "--recovery-private-key", keyFile, "-o", "yaml")
	cmd.Stdin = bytes.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubeseal: %v\n%s", err, out)
	}
	// "czNjcmV0" is base64("s3cret").
	for _, want := range []string{"PASSWORD: czNjcmV0", "name: db", "namespace: apps"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("unsealed output missing %q:\n%s", want, out)
		}
	}
}
