package rrr

import (
	"crypto/ecdsa"
	"errors"
)

var (
	ErrSignedDecodeSignedFailed = errors.New("decoding signed rlp struct failed")
)

// General serialisation support for consensus types that need recording in the
// blocks. For go-ethereum the target is always the Extra field in the block
// header

type BytesEncoder interface {
	EncodeToBytes(val interface{}) ([]byte, error)
}
type BytesDecoder interface {
	DecodeBytes(b []byte, val interface{}) error
}

type BytesCodec interface {
	BytesEncoder
	BytesDecoder
}

type CipherCodec struct {
	c  CipherSuite
	ed BytesCodec
}

func NewCodec(c CipherSuite, ed BytesCodec) *CipherCodec {
	return &CipherCodec{c: c, ed: ed}
}

func (codec *CipherCodec) EncodeToBytes(val interface{}) ([]byte, error) {
	return codec.ed.EncodeToBytes(val)
}

func (codec *CipherCodec) DecodeBytes(b []byte, val interface{}) error {
	return codec.ed.DecodeBytes(b, val)
}

func (codec *CipherCodec) Keccak256Hash(b ...[]byte) Hash {
	return Keccak256Hash(codec.c, b...)
}

func (codec *CipherCodec) BytesToPublic(pub []byte) (*ecdsa.PublicKey, error) {
	return BytesToPublic(codec.c, pub)
}

func (codec *CipherCodec) NodeIDBytesFromPub(pub *ecdsa.PublicKey) []byte {
	return NodeIDBytesFromPub(codec.c, pub)
}

func (codec *CipherCodec) NodeIDFromPubBytes(pub []byte) (Hash, error) {
	return NodeIDFromPubBytes(codec.c, pub)
}

func (codec *CipherCodec) NodeIDFromPub(pub *ecdsa.PublicKey) Hash {
	return NodeIDFromPub(codec.c, pub)
}

// VerifyRecoverNodeSig verifies that sig over digest was produced by
// the public key for the node identified by nodeID and returns the recovered
// public key bytes. This works because the nodeID is the hash of the nodes
// public key.
func (codec *CipherCodec) VerifyRecoverNodeSig(
	nodeID Hash, digest, sig []byte) (bool, []byte, error) {
	return VerifyRecoverNodeSig(codec.c, nodeID, digest, sig)
}

// VerifyNodeSig verifies that sig over digest was produced by the
// public key for the node identified by nodeID. This works because the nodeID
// is the hash of the nodes public key.
func (codec *CipherCodec) VerifyNodeSig(
	nodeID Hash, digest, sig []byte) bool {
	return VerifyNodeSig(codec.c, nodeID, digest, sig)
}

type signedEncoding struct {
	Encoded []byte
	Sig     [65]byte
}

func (codec *CipherCodec) SignedEncode(k *ecdsa.PrivateKey, v interface{}) ([65]byte, []byte, error) {
	var err error

	se := &signedEncoding{}
	var b []byte

	if se.Encoded, err = codec.EncodeToBytes(v); err != nil {
		return [65]byte{}, nil, err
	}

	h := codec.c.Keccak256(se.Encoded)

	if b, err = codec.c.Sign(h, k); err != nil {
		return [65]byte{}, nil, err
	}

	copy(se.Sig[:], b)

	if b, err = codec.EncodeToBytes(se); err != nil {
		return [65]byte{}, nil, err
	}
	return se.Sig, b, nil
}

// decodeSigned decodes a hash and its 65 byte ecdsa signture and recovers the
// puplic key. In this implementation, the recovered public key is the RRR long
// term identity and we pretty much always want that to hand.
func (codec *CipherCodec) DecodeSigned(msg []byte) ([65]byte, []byte, []byte, error) {

	var err error
	var pub []byte

	se := &signedEncoding{}
	if err = codec.DecodeBytes(msg, &se); err != nil {
		return [65]byte{}, nil, nil, err
	}

	h := codec.c.Keccak256(se.Encoded)

	// recover the public key
	pub, err = codec.c.Ecrecover(h, se.Sig[:])
	if err != nil {
		return [65]byte{}, nil, nil, err
	}

	return se.Sig, pub, se.Encoded, nil
}
