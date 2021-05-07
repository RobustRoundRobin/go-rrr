package rrr

// All hashes are keccak 256 unless otherwise stated

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
)

// Quote is the 'pseudo' attestation of identity performed using node private
// keys rather than SGX. See RRR-spec 'extraData of Block0' and 'Enrolment
// data'. It is only the "Quote" refrenced in the original paper in so far as
// it will be the Qi that gets included in Block0 or in Enroln messages.  It's
// an ecdsa signature the [R || S || V] format
type Quote [65]byte

// Enrolment provides the RRR identity enrolment data.
type Enrolment struct {
	Q Quote
	U Hash // nodeid for genesis, EnrolmentBinding.U() otherwise

	// ID can be verified by reconstructing an EnrolmentBinding, getting its
	// hash, comparing that hash with U (above) and then checking that the
	// public key for the node that sealed the block with the Enrolment can
	// verify the quote.
	ID Hash // must be verified by re-creating an Enrol
}

// FillEnrolmentQuote intitialises a Quote for an identity to be enroled on the chain.
// a is the attestor. For genesis enrolment, this should be the chain creators
// private key.
// u is the 'userdata' hash to attest. For genesis identity
// enrolment it is just the enode identity directly (they are already 32 byte
// hashes). For operational enrolment it the hash of the rlp encoded
// EnrolmentBinding struct
func (codec *CipherCodec) FillEnrolmentQuote(q []byte, u Hash, a *ecdsa.PrivateKey) error {

	var err error
	var b []byte

	if len(q) != 65 {
		return fmt.Errorf("quote slice len %d, must be 65", len(q))
	}

	if b, err = codec.c.Sign(u[:], a); err != nil {
		return err
	}
	copy(q[:], b[:])

	return nil
}

// SignIdentityEnrolment fills in a quote for operational enrolment of the
// supplied nodeid. This binds the enrolment to the chain identified by
// chainID. Round is the current round of consensus. blockHash identifies the
// current head of the chain (selected branch)
func (codec *CipherCodec) SignEnrolmentBindingHash(
	q *Quote, key *ecdsa.PrivateKey, chainID Hash, nodeid Hash, round *big.Int,
	blockHash Hash, reEnrol bool,
) error {
	e := &EnrolmentBinding{
		ChainID: chainID, NodeID: nodeid, Round: round, BlockHash: blockHash, ReEnrol: reEnrol}
	u, err := codec.HashEnrolmentBinding(e)
	if err != nil {
		return err
	}
	return codec.FillEnrolmentQuote(q[:], u, key)
}

// EnrolmentBinding is rlp encoded, hashed and signed to introduce NodeID as a
// member.
type EnrolmentBinding struct {
	ChainID   Hash     // ChainID is EIP-rrr/extraData of Block0
	NodeID    Hash     // NodeID is defined by ethereum as keccak 256 ( PublicKey X || Y )
	Round     *big.Int // Round is the consensus round
	BlockHash Hash     // BlockHash is the block hash for the head of the selected chain branch
	ReEnrol   bool     // true if the identity has been enroled before.
}

// U encodes the userdata hash to sign for the enrolment.
func (codec *CipherCodec) HashEnrolmentBinding(e *EnrolmentBinding) (Hash, error) {

	u := Hash{}
	b, err := codec.EncodeToBytes(e)
	if err != nil {
		return u, err
	}
	copy(u[:], codec.c.Keccak256(b))
	return u, nil
}

// RecoverEnrolmentPublic recovers the public component of the key which signed
// the enrolment from the signature q and and the userdata hash u. For a
// genesis enrolment, that is just the nodeid directly. For operational
// enrolments, obtain u by filling in the EnrolementBinding type and calling
// HashEnrolmentBinding()
func (codec *CipherCodec) RecoverEnrolmentPublic(q Quote, u Hash) (*ecdsa.PublicKey, error) {
	return RecoverPublic(codec.c, u[:], q[:])
}

// RecoverEnrolerID recovers the identity that signed the enrolment hash u.
func (codec *CipherCodec) RecoverEnrolerID(q Quote, u Hash) (Hash, error) {
	p, err := codec.c.Ecrecover(u[:], q[:])
	if err != nil {
		return Hash{}, err
	}
	id := Hash{}
	copy(id[:], codec.c.Keccak256(p[1:65]))
	return id, nil
}
