package rrr

import (
	"crypto/ecdsa"
)

// ExtraHeader is the common header for the genesis block and consensus produced blocks
type ExtraHeader struct {
	SealTime []byte // result of time.Now().UTC().MarshalBinary() at seal time
	Seed     []byte // VRF beta output, alpha is previous seed
	Proof    []byte // VRF proof
	Enrol    []Enrolment
}

// ExtraData is the complete (minus sig) RRR consensus data included on each block
type ExtraData struct {
	ExtraHeader
	Intent  Intent
	Confirm []Endorsement
}

// SignedExtraData is ExtraData with signature
type SignedExtraData struct {
	ExtraData
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

// SignedEncode signs and encodes the extra data
func (codec *CipherCodec) EncodeSignExtraData(e *SignedExtraData, k *ecdsa.PrivateKey) ([]byte, error) {
	var err error
	var b []byte
	e.Sig, b, err = codec.SignedEncode(k, e.ExtraData)
	return b, err
}

// DecodeSigned decodes a SignedExtraData from the stream
func (codec *CipherCodec) DecodeSignedExtraData(e *SignedExtraData, b []byte) ([]byte, error) {

	sig, pub, body, err := codec.DecodeSigned(b)
	if err != nil {
		return nil, err
	}
	e.Sig = sig

	// Do the defered decoding of the Endorsement now we have verified the sig
	if err = codec.DecodeBytes(body, &e.ExtraData); err != nil {
		return nil, err
	}
	return pub, nil
}
