package rrr

import (
	"crypto/ecdsa"
)

// Intent declares a leader candidates intent to seal a block
type Intent struct {
	// ChainID is established in the extradata of the genesis block
	ChainID Hash
	// NodeID is Keccak256 ( PublicKey X || Y )
	NodeID Hash

	// The oldest identity in the active selection derived from the branch
	// starting at the parent of the proposed block. This makes it more
	// efficient to determine if leader candidates are idle.
	OldestID Hash

	// RoundNumber is the block number proposed.
	RoundNumber uint64
	// ParentHash parent block hash
	ParentHash Hash
	// TxHash is the hash of the transactions (merkle root for block)
	TxHash Hash
}

// Hash hashes the intent
func (codec *CipherCodec) HashIntent(i *Intent) (Hash, error) {

	var err error
	var b []byte
	if b, err = codec.EncodeToBytes(i); err != nil {
		return Hash{}, err
	}

	h := Hash{}
	copy(h[:], codec.c.Keccak256(b))
	return h, nil
}

// SignedIntent holds the Intent plus its sig
type SignedIntent struct {
	Intent
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

// EncodeSignIntent encodes the intent body, signs the result and returns the
// serialised encoding of the result. k will typically be a leader candidate
// private key.
func (codec *CipherCodec) EncodeSignIntent(i *SignedIntent, k *ecdsa.PrivateKey) ([]byte, error) {

	var err error
	var b []byte
	i.Sig, b, err = codec.SignedEncode(k, &i.Intent)
	return b, err
}

// DecodeSigned decodes ... (does not verify)
func (codec *CipherCodec) DecodeSignedIntent(i *SignedIntent, b []byte) ([]byte, error) {

	sig, pub, body, err := codec.DecodeSigned(b)
	if err != nil {
		return nil, err
	}
	i.Sig = sig

	// Do the defered decoding of the Intent now we have verified the sig
	if err = codec.DecodeBytes(body, &i.Intent); err != nil {
		return nil, err
	}

	return pub, nil
}
