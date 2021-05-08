// +build csecp

package secp256k1suite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/secp256k1" // see go.mod this is 'replaced'
	"golang.org/x/crypto/sha3"
)

// NewCipherSuite returns the CipherSuite selected by the package build tags (csecp present or not)
func NewCipherSuite() CipherSuite {
	return &SECP256k1Suite{}
}

// See comment in secp256k1_nocgo.go

type SECP256k1Suite struct{}

func (c *SECP256k1Suite) Curve() elliptic.Curve {
	return secp256k1.S256()
}

// Keccak256 returns a digest suitable for Sign. (draft sha3 before the padding was added)
func (c *SECP256k1Suite) Keccak256(image ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, b := range image {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}

// Sign is given a digest to sign.
func (c *SECP256k1Suite) Sign(digest []byte, key *ecdsa.PrivateKey) ([]byte, error) {

	if len(digest) != 32 {
		return nil, fmt.Errorf("bad digest len %d, require 32", len(digest))
	}

	nbytes := key.Params().BitSize / 8

	// encode the private key as a big endian slice of bytes
	var d []byte
	if key.D.BitLen()/8 >= nbytes {
		d = key.D.Bytes()
	} else {
		d = make([]byte, nbytes)
		ReadBits(key.D, d)
	}

	return secp256k1.Sign(digest, d)
}

// VerifySignature verifies
func (c *SECP256k1Suite) VerifySignature(pub, digest, sig []byte) bool {
	return secp256k1.VerifySignature(pub, digest, sig)
}

// Ecrecover a public key from a recoverable signature.
func (c *SECP256k1Suite) Ecrecover(digest, sig []byte) ([]byte, error) {
	return secp256k1.RecoverPubkey(digest, sig)
}
