package rrr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	// number of bits in a big.Word
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes = wordBits / 8
)

// borrowed
func ReadBits(bigint *big.Int, buf []byte) {
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

// Pub2NodeIDBytes NodeID is Keccak256 (Pub.X || Pub.Y )
// In contexts where we have the id and a signature, we can recover the pub key
// of the signer using Ecrecover
func Pub2NodeIDBytes(c CipherSuite, pub *ecdsa.PublicKey) []byte {
	buf := make([]byte, 64)
	ReadBits(pub.X, buf[:32])
	ReadBits(pub.Y, buf[32:])
	return c.Keccak256(buf)
}

// PubBytes2NodeID gets a node id from the bytes of an ecdsa public key
func PubBytes2NodeID(c CipherSuite, pub []byte) (Hash, error) {
	if len(pub) != 65 {
		return Hash{}, fmt.Errorf("raw pubkey must be 65 bytes long")
	}
	h := Hash{}
	copy(h[:], c.Keccak256(pub[1:]))
	return h, nil
}

// Pub2NodeID gets a node id from an ecdsa pub key
func Pub2NodeID(c CipherSuite, pub *ecdsa.PublicKey) Hash {
	h := Hash{}
	copy(h[:], Pub2NodeIDBytes(c, pub))
	return h
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

// SignerNodeID gets the recovers the signers node id  from the signature
func (h Hash) SignerNodeID(c CipherSuite, sig []byte) (Hash, error) {
	pub, err := h.SignerPub(c, sig)
	if err != nil {
		return Hash{}, err
	}
	return Pub2NodeID(c, pub), nil
}

// SignerEnodeID recovers the enode id for the signer of the hash
func (h Hash) SignerEnodeID(c CipherSuite, sig []byte) ([]byte, error) {
	pub, err := RecoverPublic(c, h[:], sig)
	if err != nil {
		return nil, err
	}
	return elliptic.Marshal(c.Curve(), pub.X, pub.Y)[1:], nil
}
