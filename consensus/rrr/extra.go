package rrr

import (
	"crypto/ecdsa"
)

// ExtraData is the complete (minus sig) RRR consensus data included on each block
type ExtraData struct {
	// SealTime is not part of the protocol. It is used for reporting
	// disemination latencey. It is the unix time on the sealers system.
	SealTime uint64
	Intent   Intent
	Confirm  []Endorsement
	Enrol    []Enrolment
	Seed     []byte // VRF beta output, alpha is previous seed
	Proof    []byte // VRF proof
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
