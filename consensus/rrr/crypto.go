package rrr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// Hash is a hash. We always work with Keccak256 (draft sha3)
type Hash [32]byte

// Address is the ethereum style right most 20 bytes of Keccak256 (pub.X || pub.Y )
type Address [20]byte

// CipherSuite abstracts essential cryptographic primitives used by rrr. It
// exists principally to avoid licensing issues and circular dependencies on
// go-ethereum. Implementations are assumed to be EC secp256k1 + draft sha3.
// This interface does not allow for algorithmic agility of any kind.
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
	HashLen       = 32
)

func Hex2Hash(s string) Hash {
	h := Hash{}
	if s[:2] == "0x" {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = s[:len(s)-1]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	if len(b) > len(h) {
		copy(h[:], b[len(b)-HashLen:])
		return h
	}
	copy(h[:], b)
	return h
}

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

// NodeIDBytesFromPub NodeID is Keccak256 (Pub.X || Pub.Y )
// In contexts where we have the id and a signature, we can recover the pub key
// of the signer using Ecrecover
func NodeIDBytesFromPub(c CipherSuite, pub *ecdsa.PublicKey) []byte {
	buf := make([]byte, 64)
	ReadBits(pub.X, buf[:32])
	ReadBits(pub.Y, buf[32:])
	return c.Keccak256(buf)
}

// NodeIDFromPubBytes gets a node id from the bytes of an ecdsa public key
func NodeIDFromPubBytes(c CipherSuite, pub []byte) (Hash, error) {
	if len(pub) != 65 {
		return Hash{}, fmt.Errorf("raw pubkey must be 65 bytes long")
	}
	h := Hash{}
	copy(h[:], c.Keccak256(pub[1:]))
	return h, nil
}

// NodeIDFromPub gets a node id from an ecdsa pub key
func NodeIDFromPub(c CipherSuite, pub *ecdsa.PublicKey) Hash {
	h := Hash{}
	copy(h[:], NodeIDBytesFromPub(c, pub))
	return h
}

// VerifyNodeSig verifies if sig over digest was produced using the
// private key corresponding to nodeID. We EC recover the public key from the
// digest and the signature and then compare the hash of the recovered public
// key with the node ID. As ethereum node identities are the hash of the node's
// public key, this is equivelant to verification using the public key.
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

// Address gets an address from a hash
func (h Hash) Address() Address {
	a := Address{}
	copy(a[:], h[12:])
	return a
}

// Hex gets the hex string of the Hash
func (h Hash) Hex() string {
	return hex.EncodeToString(h[:])
}

// Hex gets the hex string for the Address
func (a Address) Hex() string {
	return hex.EncodeToString(a[:])
}

// SignerPub recovers the public key that signed h
func (h Hash) SignerPub(c CipherSuite, sig []byte) (*ecdsa.PublicKey, error) {
	return RecoverPublic(c, h[:], sig)
}

// NodeIDFromSig gets the recovers the signers node id  from the signature
func (h Hash) NodeIDFromSig(c CipherSuite, sig []byte) (Hash, error) {
	pub, err := h.SignerPub(c, sig)
	if err != nil {
		return Hash{}, err
	}
	return NodeIDFromPub(c, pub), nil
}

// EnodeIDFromSig recovers the enode id for the signer of the hash
func (h Hash) EnodeIDFromSig(c CipherSuite, sig []byte) ([]byte, error) {
	pub, err := RecoverPublic(c, h[:], sig)
	if err != nil {
		return nil, err
	}
	return elliptic.Marshal(c.Curve(), pub.X, pub.Y)[1:], nil
}
