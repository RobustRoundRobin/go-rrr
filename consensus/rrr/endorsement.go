package rrr

import (
	"crypto/ecdsa"
)

// Endorsement represents the unsigned approval of a leader candidates intent.
type Endorsement struct {
	ChainID    Hash
	IntentHash Hash
	EndorserID Hash // NodeID of endorser
}

// SignedEndorsement is the approval with the appropriate sig
type SignedEndorsement struct {
	Endorsement
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

// EncodeSignEndorsement encode and sign an endorsment
func (codec *CipherCodec) EncodeSignEndorsement(e *SignedEndorsement, k *ecdsa.PrivateKey) ([]byte, error) {

	var err error
	var b []byte
	e.Sig, b, err = codec.SignedEncode(k, e.Endorsement)

	return b, err
}

// DecodeSigned decodes the endorsment and returns the signers ecrecovered public key
func (codec *CipherCodec) DecodeSignedEndorsement(e *SignedEndorsement, b []byte) ([]byte, error) {

	sig, pub, body, err := codec.DecodeSigned(b)
	if err != nil {
		return nil, err
	}
	e.Sig = sig

	if err = codec.DecodeBytes(body, &e.Endorsement); err != nil {
		return nil, err
	}
	return pub, nil
}
