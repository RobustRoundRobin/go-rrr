package rrr

import "fmt"

// BlockActivity is the decoded RRR consensus block activity data from the
// block header extra data.
type BlockActivity struct {
	Confirm     []Endorsement
	Enrol       []Enrolment
	SealerID    Hash
	SealerPub   []byte
	OldestID    Hash
	RoundNumber uint64
}

// Decode decodes the RRR consensus activity data from the header extra data.
// Any activity previously held is completely discarded
func (codec *CipherCodec) DecodeBlockActivity(a *BlockActivity, chainID Hash, header BlockHeader) error {

	var err error
	var se *SignedExtraData

	a.Confirm = nil
	a.Enrol = nil
	a.SealerID = Hash{}
	a.SealerPub = nil
	a.OldestID = Hash{}

	// Common and fast path first
	if header.GetNumber().Cmp(big0) > 0 {
		se, a.SealerID, a.SealerPub, err = codec.DecodeHeaderSeal(header)
		if err != nil {
			return err
		}
		a.Confirm = se.ExtraData.Confirm
		a.Enrol = se.ExtraData.Enrol
		a.OldestID = se.Intent.OldestID
		a.RoundNumber = se.Intent.RoundNumber
		return nil
	}

	// Genesis block needs special handling.
	ge := &GenesisExtraData{}
	if err = codec.DecodeGenesisExtra(header.GetExtra(), ge); err != nil {
		return fmt.Errorf("%v: %w", err, ErrDecodingGenesisExtra)
	}

	// But do require consistency, if it has been previously decoded
	h0 := Hash{}
	if chainID != h0 && chainID != ge.ChainID {
		return fmt.Errorf(
			"genesis header with incorrect chainID: %w", ErrDecodingGenesisExtra)
	}

	// Get the genesis signer public key and node id. Do this derivation of
	// node id and public key unconditionally regardless of wheter we think we
	// have the information to hand - it is just safer that way.
	a.SealerPub, err = codec.c.Ecrecover(ge.Enrol[0].U[:], ge.Enrol[0].Q[:])
	if err != nil {
		return fmt.Errorf("%v:%w", err, errGensisIdentitiesInvalid)
	}

	copy(a.SealerID[:], codec.c.Keccak256(a.SealerPub[1:65]))
	a.OldestID = a.SealerID

	a.Confirm = []Endorsement{}
	a.Enrol = ge.Enrol

	return nil
}
