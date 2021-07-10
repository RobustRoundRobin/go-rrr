package rrr

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/vechain/go-ecvrf"
	"golang.org/x/crypto/sha3"
)

var (
	errInsuficientSeedContribs    = errors.New("each genesis identity must contribute to the initial random seed")
	ErrGenesisExtraDigestMismatch = errors.New("the included digest of the genesis extra doesn't match the actual")
)

// Alpha encodes the seed contribution for a single genesis identity.
// The initial seed is calculted using the keccak of the catentaion of each contribution::
//   alpha = KeccaK(contribution-id0 | ... | contribution-idN)
//   seed, pi =  VRF-Prove(alpha).
// The original paper suggests a warmup phase in the consensus protocol which
// utilises RandHound and this is planed for future work.
type Alpha struct {
	Contribution Hash
	Sig          [65]byte
}

// ChainInit holds the RRR consensus genesis configuration, including
// genesis enroled identities
type ChainInit struct {
	ExtraHeader
	Alpha []Alpha // one per enrolment, contributions are catenated in ident genesis age order
}

// GenesisExtraData  adds the ChainID which is the hash of the ChainInit
type GenesisExtraData struct {
	ChainInit
	ChainID Hash // Hash of encoded ChainInit
}

// IdentInit creates, or extends, the identity initialisation vector for the
// extraData in the genesis block. init is nil or the currently included
// identities. One or more nodeids are passed as the trailing parameters. The
// updated init vector is returned. See EIP-rrr/extraData of Block0
func IdentInit(
	codec *CipherCodec, ck *ecdsa.PrivateKey, init []Enrolment, nodeids ...Hash) ([]Enrolment, error) {

	start := len(init)
	init = append(init, make([]Enrolment, len(nodeids))...)

	// Use a mostly empty binding for genesis. We do to limit the special
	// handling for the genesis block when validating enrolments.
	eb := EnrolmentBinding{}

	for i, id := range nodeids {

		eb.NodeID = id
		u, err := codec.HashEnrolmentBinding(&eb)
		if err != nil {
			return nil, err
		}

		// In this implementation it is always going to be the block sealer key
		// 'attesting' each identity enroled in a block. And that key signs the
		// whole block header. But we do it this way regardless - for alignment
		// with future posibilities and because it is actually quite convenient
		// in other places.

		err = codec.FillEnrolmentQuote(init[start+i].Q[:], u, ck)
		if err != nil {
			return init, err
		}

		copy(init[start+i].U[:], u[:])
		copy(init[start+i].ID[:], id[:])
	}
	return init, nil
}

// Populate fills in a ChainInit ready for encoding in the genesis extraData
// See EIP-rrr/extraData of Block0/9.
func (codec *CipherCodec) PopulateChainInit(
	ci *ChainInit, ck *ecdsa.PrivateKey, initIdents []Enrolment, alphaContrib map[Hash]Alpha) error {

	signerNodeID := NodeIDFromPub(codec.c, &ck.PublicKey)

	// Convenience for single node and small networks. It will be counter
	// productive, from a human security perspective, to require the genesis
	// node to fill this in if they don't want to.
	if _, ok := alphaContrib[Hash(signerNodeID)]; !ok {

		a := Alpha{}
		if _, err := rand.Read(a.Contribution[:]); err != nil {
			return err
		}
		b, err := codec.c.Sign(a.Contribution[:], ck)
		if err != nil {
			return err
		}
		copy(a.Sig[:], b)
	}

	ci.Alpha = make([]Alpha, 0, len(initIdents))

	hasher := sha3.NewLegacyKeccak256()

	// NOTICE: hashes are catenated in the order the identities are listed in
	// the genesis enrolment

	for _, ident := range initIdents {

		var ok bool
		var a Alpha

		if a, ok = alphaContrib[Hash(ident.ID)]; !ok {
			continue
		}

		pub, err := codec.c.Ecrecover(a.Contribution[:], a.Sig[:])
		if err != nil {
			return fmt.Errorf("recovering seed contribution for %s contrib=%s sig=%s: %w",
				ident.ID.Hex(), a.Contribution.Hex(), hex.EncodeToString(a.Sig[:]), err)
		}
		nodeID, err := NodeIDFromPubBytes(codec.c, pub)
		if err != nil {
			return fmt.Errorf("getting nodeid from (sig recovered) pub for %s: %w", ident.ID.Hex(), err)
		}
		if nodeID != ident.ID {
			return fmt.Errorf("invalid signature for seed contribution from %s", ident.ID.Hex())
		}
		// Signature is valid
		hasher.Write(a.Contribution[:])
		ci.Alpha = append(ci.Alpha, a)
	}

	if len(ci.Alpha) < len(initIdents) {
		return fmt.Errorf(
			"have %d, want %d: %w",
			len(ci.Alpha), len(initIdents), errInsuficientSeedContribs)
	}

	alpha := hasher.Sum(nil)

	vrf := ecvrf.NewSecp256k1Sha256Tai()
	seed, proof, err := vrf.Prove(ck, alpha)
	if err != nil {
		return err
	}

	ci.Enrol = make([]Enrolment, len(initIdents))
	copy(ci.Enrol, initIdents)

	ci.Seed = make([]byte, len(seed))
	copy(ci.Seed, seed)

	ci.Proof = make([]byte, len(proof))
	copy(ci.Proof, proof)

	b, err := time.Now().UTC().MarshalBinary()
	if err != nil {
		return err
	}
	ci.SealTime = b

	return nil
}

// ChainID returns the ChainID
func (codec *CipherCodec) ChainID(ci *ChainInit) (Hash, error) {

	id := Hash{}
	b, err := codec.EncodeToBytes(ci)
	if err != nil {
		return id, err
	}
	copy(id[:], codec.c.Keccak256(b))
	return id, err
}

// EncodeHashGenesisExtraData encodes
func (codec *CipherCodec) EncodeHashGenesisExtraData(gd *GenesisExtraData) ([]byte, error) {

	var err error
	var b []byte

	if b, err = codec.EncodeToBytes(gd.ChainInit); err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeGenesisExtra decodes the RRR genesis extra data
func (codec *CipherCodec) DecodeGenesisExtra(genesisExtra []byte, extra *GenesisExtraData) error {

	if err := codec.DecodeBytes(genesisExtra, &extra.ChainInit); err != nil {
		return err
	}
	copy(extra.ChainID[:], codec.c.Keccak256(genesisExtra))

	return nil
}

func (codec *CipherCodec) DecodeHeaderSeal(header BlockHeader) (*SignedExtraData, Hash, []byte, error) {

	var err error
	var pub []byte
	var sealerID Hash

	if header.GetNumber().Cmp(big0) == 0 {
		return nil, Hash{}, nil, fmt.Errorf("the genesis block is not compatible with decodeHeaderSeal")
	}

	// if len(header.Extra) < RRRExtraVanity {
	// 	return nil, Hash{}, nil, fmt.Errorf("RRR missing extra data on block header")
	// }
	// seal := header.Extra[RRRExtraVanity:]
	seal := header.GetSeal()

	se := &SignedExtraData{}

	if pub, err = codec.DecodeSignedExtraData(se, seal); err != nil {
		return nil, Hash{}, nil, err
	}
	sealerID, err = NodeIDFromPubBytes(codec.c, pub)
	if err != nil {
		return nil, Hash{}, nil, err
	}

	return se, sealerID, pub, nil
}
