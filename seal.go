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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

// sealedSecret is a bitnami.com/v1alpha1 SealedSecret. It is returned as
// JSON so clients can commit it in whatever format their repository uses.
type sealedSecret struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   objectMeta `json:"metadata"`
	Spec       struct {
		EncryptedData map[string]string `json:"encryptedData"`
		Template      struct {
			Metadata objectMeta `json:"metadata"`
			Type     string     `json:"type,omitempty"`
		} `json:"template"`
	} `json:"spec"`
}

type objectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// sealStrict encrypts every value with strict scope (label "namespace/name").
func sealStrict(pub *rsa.PublicKey, s secretSpec) (*sealedSecret, error) {
	label := []byte(s.Namespace + "/" + s.Name)
	out := &sealedSecret{APIVersion: "bitnami.com/v1alpha1", Kind: "SealedSecret",
		Metadata: objectMeta{Name: s.Name, Namespace: s.Namespace}}
	out.Spec.EncryptedData = make(map[string]string, len(s.Data))
	for k, v := range s.Data {
		ct, err := hybridEncrypt(rand.Reader, pub, v, label)
		if err != nil {
			return nil, fmt.Errorf("encrypt %q: %w", k, err)
		}
		out.Spec.EncryptedData[k] = base64.StdEncoding.EncodeToString(ct)
	}
	out.Spec.Template.Metadata = objectMeta{Name: s.Name, Namespace: s.Namespace,
		Labels: s.Labels, Annotations: s.Annotations}
	out.Spec.Template.Type = s.Type
	return out, nil
}
