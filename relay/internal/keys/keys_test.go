package keys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/aman-dhakar-191/androvia/relay/internal/keys"
	"github.com/aman-dhakar-191/androvia/relay/internal/testutil"
)

func TestParseP256(t *testing.T) {
	d := testutil.NewDevice(t)
	if _, err := keys.ParseP256(d.SPKI); err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsader, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	for name, b := range map[string][]byte{"nil": nil, "garbage": []byte("x"), "P-384": p384der, "RSA": rsader, "truncated": d.SPKI[:20]} {
		if _, err := keys.ParseP256(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestVerify(t *testing.T) {
	a, b := testutil.NewDevice(t), testutil.NewDevice(t)
	msg := []byte("m")
	if !keys.Verify(a.SPKI, msg, a.Sign(msg)) {
		t.Fatal("valid signature rejected")
	}
	if keys.Verify(a.SPKI, msg, b.Sign(msg)) || keys.Verify(a.SPKI, []byte("n"), a.Sign(msg)) || keys.Verify(a.SPKI, msg, nil) || keys.Verify(nil, msg, a.Sign(msg)) {
		t.Fatal("bad signature accepted")
	}
}

func TestIDMatchesTheKey(t *testing.T) {
	d := testutil.NewDevice(t)
	if keys.ID(d.SPKI) != d.ID || len(d.ID) != 64 {
		t.Fatal("id is not the key hash")
	}
}

func TestValidLabel(t *testing.T) {
	for _, ok := range []string{"a", "Pixel 8 (work)", strings.Repeat("é", 64)} {
		if keys.ValidLabel(ok) != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 65), "a\nb", "a\x00", "tab\t"} {
		if keys.ValidLabel(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
