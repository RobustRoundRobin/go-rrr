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

// SignedEncode encode and sign an endorsment
func (e *SignedEndorsement) SignedEncode(c CipherSuite, rlp RLPEncoder, k *ecdsa.PrivateKey) ([]byte, error) {

	var err error
	var b []byte
	e.Sig, b, err = SignedEncode(c, rlp, k, &e.Endorsement)

	return b, err
}

// VerifyNodeSig verifies that the supplied node id signed the endorsement
func (e *SignedEndorsement) VerifyNodeSig(c CipherSuite, rlp RLPEncoder, nodeID Hash) (bool, error) {
	return VerifyNodeSignedEncoding(c, rlp, nodeID, e.Sig[:], &e.Endorsement)
}

// DecodeSigned decodes the endorsment and returns the signers ecrecovered public key
func (e *SignedEndorsement) DecodeSigned(c CipherSuite, rlp RLPDecoder, b []byte) ([]byte, error) {

	sig, pub, body, err := DecodeSigned(c, rlp.ByteStream(b))
	if err != nil {
		return nil, err
	}
	e.Sig = sig

	if err = rlp.DecodeBytes(body, &e.Endorsement); err != nil {
		return nil, err
	}
	return pub, nil
}
