package rrr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
)

// Hash is a hash. We always work with Keccak256, same as ethereum
type Hash [32]byte

// Address is the ethereum style right most 20 bytes of Keccak256 (pub.X || pub.Y )
type Address [20]byte

// CipherSuite exists principally to avoid licensing issues and circular
// dependencies on go-ethereum
// Notice: This is assumed to be EC secp256k1 + legacy sha3
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

// PubMarshal converts public ecdsa key into the uncompressed form specified in section 4.3.6 of ANSI X9.62
func PubMarshal(c CipherSuite, pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(c.Curve(), pub.X, pub.Y)
}

const (
	AddressLength = 20
)

// Keccak256Hash hashes a variable number of byte slices and returns a Hash
func Keccak256Hash(c CipherSuite, b ...[]byte) Hash {
	h := Hash{}
	copy(h[:], c.Keccak256(b...))
	return h
}

func PubToAddress(c CipherSuite, pub *ecdsa.PublicKey) Address {
	m := PubMarshal(c, pub)
	b := c.Keccak256(m[1:])[12:]
	a := Address{}
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
	return a
}

// func

// VerifyNodeSignature verifies if sig over digest was produced using the
// private key corresponding to nodeID. We EC recover the public key from the
// digest and the signature and then compare the hash of the recovered public
// key with the node ID. As ethereum node identities are the hash of the node's
// public key, This is equivelant to verification using the public key.
//
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Public_key_recovery:
//
//  "The recovery algorithm can only be used to check validity of a signature if
//  the signer's public key (or its hash) is known beforehand"
//
// Note: Use VerifyRecoverNodeSig if you want the err from Ecrecover rather than true/false
func VerifyNodeSig(c CipherSuite, nodeID Hash, digest, sig []byte) bool {

	recoveredPub, err := c.Ecrecover(digest, sig)
	if err != nil {
		return false
	}

	if !bytes.Equal(nodeID[:], c.Keccak256(recoveredPub[1:65])) {
		return false
	}

	return true
}

func VerifyRecoverNodeSig(c CipherSuite, nodeID Hash, digest, sig []byte) (bool, []byte, error) {

	recoveredPub, err := c.Ecrecover(digest, sig)
	if err != nil {
		return false, nil, err
	}

	if !bytes.Equal(nodeID[:], c.Keccak256(recoveredPub[1:65])) {
		return false, recoveredPub, nil
	}
	return true, recoveredPub, nil
}

// RecoverPublic ...
func RecoverPublic(c CipherSuite, h []byte, sig []byte) (*ecdsa.PublicKey, error) {

	// Recover the public signing key bytes in uncompressed encoded form
	p, err := c.Ecrecover(h, sig)
	if err != nil {
		return nil, err
	}

	// re-build the public key for the private key used to sign the userdata
	// hash
	//
	// per 2.3.4 sec1-v2 for uncompresed representation "otherwise the leftmost
	// octet of the octetstring is removed"

	pub := &ecdsa.PublicKey{Curve: c.Curve(), X: new(big.Int), Y: new(big.Int)}
	pub.X.SetBytes(p[1 : 1+32])
	pub.Y.SetBytes(p[1+32 : 1+64])
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("invalid secp256k1 curve point")
	}
	return pub, nil
}

func BytesToPublic(c CipherSuite, b []byte) (*ecdsa.PublicKey, error) {

	if len(b) != 65 {
		return nil, errors.New("pub must be 65 bytes")
	}

	// re-build the public key for the private key used to sign the userdata
	// hash
	//
	// per 2.3.4 sec1-v2 for uncompresed representation "otherwise the leftmost
	// octet of the octetstring is removed"

	pub := &ecdsa.PublicKey{Curve: c.Curve(), X: new(big.Int), Y: new(big.Int)}
	pub.X.SetBytes(b[1 : 1+32])
	pub.Y.SetBytes(b[1+32 : 1+64])
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("invalid secp256k1 curve point")
	}
	return pub, nil
}
