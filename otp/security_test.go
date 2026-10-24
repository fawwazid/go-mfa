package otp

import (
	"crypto/fips140"
	"testing"
)

func TestRejectsWeakOTPConfiguration(t *testing.T) {
	for _, opts := range [][]Option{
		{WithLength(5)}, {WithCharset("0")}, {WithCharset("00123456789")},
		{WithLength(1025)}, {WithLength(1), WithCharset("ab")},
	} {
		if _, err := Generate(opts...); err == nil {
			t.Fatal("accepted weak or excessive OTP configuration")
		}
	}
	if Validate("", "") {
		t.Fatal("accepted empty OTP")
	}
}

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	code, err := Generate()
	if err != nil || len(code) != 6 {
		t.Fatalf("generate = %q, %v", code, err)
	}
	if !Validate(code, code) || Validate("", code) {
		t.Fatal("incorrect OTP validation")
	}
}
