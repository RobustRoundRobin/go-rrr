package rrr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/sha3"
)

// Implement CryptoSuite in one place. Have not decided whether to make this a
// direct dependency or require the go-rrr consumer to provide it. Unit testing
// is likely a nightmare without this though. There are 3 candidate sources for
// an implementation with compatible licenses
//
// * github.com/ConsenSys/quorum/crypto/secp256k1 BSD 3 clause (cgo)
// * github.com/ethereum/go-ethereum/crypto/secp256k1 BSD 3 clause (cgo)
// * github.com/btcsuite/btcd/btcec ICS (not c works with no cgo)
//
// Even if we remove this from the package code, we will still need to use one
// of the above to facilitate the unit tests.

type SECP256k1SuiteBTCEC struct{}

func (c *SECP256k1SuiteBTCEC) Curve() elliptic.Curve {
	return btcec.S256()
}

// Keccak256 returns a digest suitable for Sign. (draft sha3 before the padding was added)
func (c *SECP256k1SuiteBTCEC) Keccak256(image ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, b := range image {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}

// Sign is given a digest to sign.
func (c *SECP256k1SuiteBTCEC) Sign(digest []byte, key *ecdsa.PrivateKey) ([]byte, error) {

	if len(digest) != 32 {
		return nil, fmt.Errorf("bad digest len %d, require 32", len(digest))
	}

	sig, err := btcec.SignCompact(
		btcec.S256(), (*btcec.PrivateKey)(key), digest, false)

	if err != nil {
		return nil, err
	}

	// move the recovery id to the end
	v := sig[0] - 27
	copy(sig, sig[1:])
	sig[64] = v
	return sig, nil
}

// XXX: LICENSE ISSUE LGPL vs MIT
// XXX: TODO Will have to write this again or get permission to re-license. in
// any event it is a *very* close translation of
// go-ethereum/crypto/secp256k1_nocgo.go VerifySignature and Ecrecover. Those
// files are LGPL. If we chose to make the caller provide this we can probably
// move this to the tests and license a single file in the tests with the
// tainted license. the tests are not linked into the package.
var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

// VerifySignature verifies
func (c *SECP256k1SuiteBTCEC) VerifySignature(pub, digest, sig []byte) bool {
	if len(digest) != 32 {
		// fmt.Errorf("bad digest len %d, require 32", len(digest))
		return false
	}
	if len(sig) != 64 {
		// fmt.Errorf("bad sig len %d, require 64", len(digest))
		return false
	}

	// make a btec format sig
	btsig := &btcec.Signature{
		R: new(big.Int).SetBytes(sig[:32]),
		S: new(big.Int).SetBytes(sig[32:])}

	btpub, err := btcec.ParsePubKey(pub, btcec.S256())
	if err != nil {
		return false
	}
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	if btsig.S.Cmp(secp256k1halfN) > 0 {
		return false
	}
	return btsig.Verify(digest, btpub)
}

// Ecrecover a public key from a recoverable signature.
func (c *SECP256k1SuiteBTCEC) Ecrecover(digest, sig []byte) ([]byte, error) {

	btcsig := make([]byte, 65)
	btcsig[0] = sig[64] + 27
	copy(btcsig[1:], sig)

	btpub, _, err := btcec.RecoverCompact(btcec.S256(), btcsig, digest)
	pub := (*ecdsa.PublicKey)(btpub)

	if err != nil {
		return nil, err
	}
	bytes := (*btcec.PublicKey)(pub).SerializeUncompressed()
	return bytes, err
}
