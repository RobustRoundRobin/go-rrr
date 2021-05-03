package rrr

import (
	"crypto/ecdsa"
	"errors"
)

var (
	ErrSignedDecodeSignedFailed = errors.New("decoding signed rlp struct failed")
)

type RLPEncoder interface {
	EncodeToBytes(val interface{}) ([]byte, error)
	RawValue(b []byte) interface{}
}

type RLPStream interface {
	List() (size uint64, err error)
	ListEnd() error
	Raw() ([]byte, error)
	Bytes() ([]byte, error)
}

type RLPDecoder interface {
	ByteStream(b []byte) RLPStream
	DecodeBytes(b []byte, val interface{}) error
}

// VerifyNodeSignedEncoding verifies that sig was produced by the public key for
// the node identified by nodeID. The nodeID is the hash of the nodes public
// key. So rather that a typical verify where the r co-ords are compared, we
// recover the full public key and hash it to get the node id of the signer.
func VerifyNodeSignedEncoding(c CipherSuite, rlp RLPEncoder, nodeID Hash, sig []byte, v interface{}) (bool, error) {

	var err error
	var b []byte

	// Recover the public key which produced sig over hash(rlp(v)) and derive
	// the corresponding node id.
	if b, err = rlp.EncodeToBytes(v); err != nil {
		return false, err
	}

	return VerifyNodeSig(c, nodeID, c.Keccak256(b), sig), nil
}

func SignedEncode(
	c CipherSuite, rlp RLPEncoder, k *ecdsa.PrivateKey, v interface{}) ([65]byte, []byte, error) {
	var err error
	var b []byte
	var sig [65]byte

	list := make([]interface{}, 2)

	if b, err = rlp.EncodeToBytes(v); err != nil {
		return [65]byte{}, nil, err
	}
	list[0] = rlp.RawValue(b)

	h := c.Keccak256(b)

	if b, err = c.Sign(h, k); err != nil {
		return [65]byte{}, nil, err
	}

	copy(sig[:], b)

	list[1] = b

	if b, err = rlp.EncodeToBytes(list); err != nil {
		return [65]byte{}, nil, err
	}
	return sig, b, nil
}

// decodeSigned decodes a hash and its 65 byte ecdsa signture and recovers the
// puplic key. In this implementation, the recovered public key is the RRR long
// term identity and we pretty much always want that to hand.
func DecodeSigned(c CipherSuite, s RLPStream) ([65]byte, []byte, []byte, error) {

	var err error
	var sig [65]byte
	var pub []byte

	if _, err = s.List(); err != nil {
		return [65]byte{}, nil, nil, err
	}

	// First item is the full encoding of the signed item, get the bytes and
	// recover the pub key using the hash of the encoded bytes
	var body []byte
	if body, err = s.Raw(); err != nil {
		return [65]byte{}, nil, nil, err
	}
	h := c.Keccak256(body)

	// read the signature
	var b []byte
	if b, err = s.Bytes(); err != nil {
		return [65]byte{}, nil, nil, err
	}
	copy(sig[:], b)

	// recover the public key
	pub, err = c.Ecrecover(h, b)
	if err != nil {
		return [65]byte{}, nil, nil, err
	}

	if err = s.ListEnd(); err != nil {
		return [65]byte{}, nil, nil, err
	}
	return sig, pub, body, nil
}
