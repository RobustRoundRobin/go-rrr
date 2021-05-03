package rrr

import (
	"crypto/ecdsa"
	"math/big"
)

// Intent declares a leader candidates intent to seal a block
type Intent struct {
	// ChainID is established in the extradata of the genesis block
	ChainID Hash
	// NodeID is Keccak256 ( PublicKey X || Y )
	NodeID Hash
	// RoundNumber is the block number proposed.
	RoundNumber *big.Int
	// FailedAttempts is the number of times the intent/confirm cycle completed
	// on the node without a new block being produced. The validity of the
	// proposer as a leader is depedent on both the RoundNumber and the
	// FailedAttempts
	FailedAttempts uint
	// ParentHash parent block hash
	ParentHash Hash
	// TxHash is the hash of the transactions (merkle root for block)
	TxHash Hash
}

// Hash hashes the intent
func (i *Intent) Hash(c CipherSuite, rlp RLPEncoder) (Hash, error) {
	var err error
	var b []byte
	if b, err = rlp.EncodeToBytes(i); err != nil {
		return Hash{}, err
	}

	h := Hash{}
	copy(h[:], c.Keccak256(b))
	return h, nil
}

// SignedIntent holds the Intent plus its sig
type SignedIntent struct {
	Intent
	// Sig is the ecdsa signature the [R || S || V] format
	Sig [65]byte
}

// SignedEncode rlp encodes the intent body, signs the result and returns the
// RLP encoding of the result. c will typically be a leader candidate private
// key.
func (i *SignedIntent) SignedEncode(
	c CipherSuite, rlp RLPEncoder, k *ecdsa.PrivateKey) ([]byte, error) {

	var err error
	var b []byte
	i.Sig, b, err = SignedEncode(c, rlp, k, &i.Intent)
	return b, err
}

// DecodeSigned decodes ...
func (i *SignedIntent) DecodeSigned(c CipherSuite, rlp RLPDecoder, b []byte) ([]byte, error) {

	sig, pub, body, err := DecodeSigned(c, rlp.ByteStream(b))
	if err != nil {
		return nil, err
	}
	i.Sig = sig

	// Do the defered decoding of the Intent now we have verified the sig
	if err = rlp.DecodeBytes(body, &i.Intent); err != nil {
		return nil, err
	}

	return pub, nil
}
