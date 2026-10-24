package hotp

import (
	"crypto"
	"encoding/base32"
	"strings"
	"testing"
)

const rfcSecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestSHA256Vector(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	code, err := GenerateCode(secret, 1, WithLength(8))
	if err != nil || code != "46119246" {
		t.Fatalf("RFC 6238 counter-1 vector=%q,%v", code, err)
	}
	if !Validate(code, secret, 1, WithLength(8)) || Validate("00000000", secret, 1, WithLength(8)) {
		t.Fatal("incorrect validation")
	}
	if _, err := GenerateCodeFromKey(key, 1, WithAlgorithm(crypto.SHA512)); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, opts := range [][]Option{{WithLength(0)}, {WithLength(5)}, {WithLength(11)}, {WithAlgorithm(0)}, {WithAlgorithm(crypto.SHA1)}, {WithAlgorithm(crypto.MD5)}} {
		if _, err := GenerateCode(rfcSecretBase32, 0, opts...); err == nil {
			t.Fatal("accepted unsupported configuration")
		}
	}
	if _, err := GenerateCodeFromKey(make([]byte, 13), 0); err == nil {
		t.Fatal("accepted short secret")
	}
	if _, err := GenerateCode(rfcSecretBase32, 0, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalBase32(t *testing.T) {
	for _, secret := range []string{"", strings.ToLower(rfcSecretBase32), rfcSecretBase32 + "====", " " + rfcSecretBase32, rfcSecretBase32 + "\n"} {
		if _, err := DecodeSecret(secret); err == nil {
			t.Fatalf("accepted noncanonical secret %q", secret)
		}
	}
}
