package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// hybridEncrypt reproduces the ciphertext format used by Sealed Secrets
// (pkg/crypto.HybridEncrypt): a random AES-256-GCM session key is wrapped
// with RSA-OAEP(SHA-256) using label, and the result is
//
//	uint16 big-endian len(rsaCiphertext) || rsaCiphertext || aesgcm(plaintext)
//
// The GCM nonce is all zeros, which is safe because every session key is
// used exactly once.
func hybridEncrypt(rnd io.Reader, pub *rsa.PublicKey, plaintext, label []byte) ([]byte, error) {
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(rnd, sessionKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rnd, pub, sessionKey, label)
	if err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(wrapped)))
	out = append(out, wrapped...)
	return aead.Seal(out, make([]byte, aead.NonceSize()), plaintext, nil), nil
}

// parseCert extracts the RSA public key from the controller's PEM certificate.
func parseCert(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("controller certificate is not a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("controller certificate does not hold an RSA key")
	}
	return pub, nil
}

// secretSpec is the part of a Secret that ends up in a SealedSecret.
type secretSpec struct {
	Namespace   string
	Name        string
	Type        string
	Labels      map[string]string
	Annotations map[string]string
	Data        map[string][]byte
}

// sealStrict encrypts every value with strict scope (label "namespace/name")
// and renders the SealedSecret manifest as YAML.
func sealStrict(pub *rsa.PublicKey, s secretSpec) (string, error) {
	label := []byte(s.Namespace + "/" + s.Name)
	enc := make(map[string]string, len(s.Data))
	for k, v := range s.Data {
		ct, err := hybridEncrypt(rand.Reader, pub, v, label)
		if err != nil {
			return "", fmt.Errorf("encrypt %q: %w", k, err)
		}
		enc[k] = base64.StdEncoding.EncodeToString(ct)
	}

	var b strings.Builder
	w := func(indent int, format string, a ...any) {
		b.WriteString(strings.Repeat("  ", indent))
		fmt.Fprintf(&b, format, a...)
		b.WriteByte('\n')
	}
	w(0, "apiVersion: bitnami.com/v1alpha1")
	w(0, "kind: SealedSecret")
	w(0, "metadata:")
	w(1, "name: %s", s.Name)
	w(1, "namespace: %s", s.Namespace)
	w(0, "spec:")
	w(1, "encryptedData:")
	for _, k := range sortedKeys(enc) {
		w(2, "%s: %s", quote(k), enc[k])
	}
	w(1, "template:")
	w(2, "metadata:")
	w(3, "name: %s", s.Name)
	w(3, "namespace: %s", s.Namespace)
	for _, m := range []struct {
		field string
		kv    map[string]string
	}{{"labels", s.Labels}, {"annotations", s.Annotations}} {
		if len(m.kv) == 0 {
			continue
		}
		w(3, "%s:", m.field)
		for _, k := range sortedKeys(m.kv) {
			w(4, "%s: %s", quote(k), quote(m.kv[k]))
		}
	}
	if s.Type != "" {
		w(2, "type: %s", quote(s.Type))
	}
	return b.String(), nil
}

// quote renders a string as a YAML double-quoted scalar. JSON string
// escaping is a subset of YAML's, so the output is always valid YAML.
func quote(s string) string {
	q, _ := json.Marshal(s)
	return string(q)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
