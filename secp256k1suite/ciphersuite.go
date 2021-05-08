package secp256k1suite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
)

// There are three (easy) candidate sources and one a little less easy
// * github.com/ConsenSys/quorum/crypto/secp256k1 BSD 3 clause (cgo)
// * github.com/btcsuite/btcd/btcec ICS (not c works with no cgo)
// * github.com/ethereum/go-ethereum/crypto/secp256k1 BSD 3 clause (cgo)
// * https://github.com/bitcoin-core/secp256k1 MIT
//
// We have direct support for the first two.

type CipherSuite interface {
	Curve() elliptic.Curve

	// Keccak256 returns a digest suitable for Sign. (draft sha3 before the padding was added)
	Keccak256(b ...[]byte) []byte

	// Sign is given a digest to sign.
	Sign(digest []byte, key *ecdsa.PrivateKey) ([]byte, error)

	// VerifySignature verifies
	VerifySignature(bub, digest, sig []byte) bool

	// Ecrecover a public key from a recoverable signature.
	Ecrecover(digest, sig []byte) ([]byte, error)
}
