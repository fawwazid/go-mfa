// Package algorithm defines the supported OTP hash algorithms.
package algorithm

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
)

var ErrUnsupported = errors.New("OTP algorithm must be SHA-256 or SHA-512")

func Params(hash crypto.Hash) (name string, keySize int, err error) {
	switch hash {
	case crypto.SHA256:
		return "SHA256", sha256.Size, nil
	case crypto.SHA512:
		return "SHA512", sha512.Size, nil
	default:
		return "", 0, ErrUnsupported
	}
}
