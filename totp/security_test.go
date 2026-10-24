package totp

import (
	"crypto"
	"crypto/fips140"
	"testing"
	"time"
)

func TestRejectsWeakMFAParameters(t *testing.T) {
	if _, err := GenerateCode(getRFCSecret(t, 32), WithLength(5)); err == nil {
		t.Fatal("accepted short code")
	}
	if _, err := GenerateCode("JBSWY3DPEHPK3PXP"); err == nil {
		t.Fatal("accepted short secret")
	}
	if _, err := GenerateSecret(crypto.SHA1); err == nil {
		t.Fatal("accepted SHA-1 secret generation")
	}
	if _, err := GenerateURL("user@example.com", "App", getRFCSecret(t, 32), WithAlgorithm(crypto.SHA1)); err == nil {
		t.Fatal("accepted SHA-1 enrollment")
	}
}

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	secret := getRFCSecret(t, 32)
	opts := []Option{WithTime(time.Unix(59, 0)), WithLength(8), WithSkew(0)}
	code, err := GenerateCode(secret, opts...)
	if err != nil || code != "46119246" {
		t.Fatalf("vector=%q,%v", code, err)
	}
	if !Validate(code, secret, opts...) || Validate("00000000", secret, opts...) {
		t.Fatal("incorrect TOTP validation")
	}
	if _, err := GenerateSecret(crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	TestRejectsWeakMFAParameters(t)
}
