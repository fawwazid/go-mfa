package hotp

import (
	"crypto/fips140"
	"testing"
)

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	TestSHA256Vector(t)
	TestInvalidConfiguration(t)
}
