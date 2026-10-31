// Package keys holds the key handling shared by devices and clients: EC P-256 public keys in X.509
// SubjectPublicKeyInfo form, ASN.1 DER ECDSA/SHA-256 signatures, and label rules.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"unicode"
)

// ParseP256 accepts only an EC P-256 public key; anything else (RSA, other curves, garbage) is rejected.
func ParseP256(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("public_key is not a valid SubjectPublicKeyInfo")
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("public_key must be an EC P-256 key")
	}
	return ek, nil
}

// Verify checks an ASN.1 DER ECDSA/SHA-256 signature over msg with the public key in spki.
func Verify(spki, msg, sig []byte) bool {
	k, err := ParseP256(spki)
	if err != nil {
		return false
	}
	h := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(k, h[:], sig)
}

// ID is the hex SHA-256 of the key, so an identifier cannot be claimed without holding the key.
func ID(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// ValidLabel enforces 1-64 printable characters.
func ValidLabel(label string) error {
	if l := len([]rune(label)); l == 0 || l > 64 {
		return errors.New("label must be 1-64 characters")
	}
	for _, r := range label {
		if !unicode.IsPrint(r) {
			return errors.New("label contains non-printable characters")
		}
	}
	return nil
}
