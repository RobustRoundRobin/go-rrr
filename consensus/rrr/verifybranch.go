package rrr

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrUnknownAncestor      = errors.New("unknown ancestor")
	ErrDecodingGenesisExtra = errors.New("failed to decode extra field from genesis block")
	ErrBadHeaderSeal        = errors.New("invalid or corrupt header seal")
	emptyNonce              = [8]byte{}
)

// This will become 'Algorithm 5 VerifyBranch' and related machinery, but its
// not there yet.

type VerifyBranchChainReader interface {

	// GetHeader retrieves a block header from the database by hash and number.
	GetHeader(hash [32]byte, number uint64) BlockHeader

	// GetHeaderByNumber retrieves a block header from the database by number.
	GetHeaderByNumber(number uint64) BlockHeader
}

func (r *EndorsmentProtocol) VerifyBranchHeaders(
	chain VerifyBranchChainReader, header BlockHeader, parents []BlockHeader) error {
	// If we want to filter blocks based on the assumption of "loosely
	// synchronised node time", this is where we should do it. (Before doing
	// any other more intensive validation)

	var err error

	number := header.GetNumber().Uint64()

	// The genesis block is the always valid dead-end. However, geth calls
	// VerifyBranchHeaders as it warms up before looking at any other blocks.
	// This is the only opportunity to collect the genesis extra data on nodes
	// that have to sync before they can participate.

	if number == 0 {

		h0 := Hash{}
		if r.genesisEx.ChainID == h0 {

			extra := header.GetExtra()
			r.logger.Info(
				"RRR VerifyBranchHeaders - genesis block", "extra",
				hex.EncodeToString(extra))
			err := r.codec.DecodeGenesisExtra(extra, &r.genesisEx)
			if err != nil {
				return err
			}
		}

		return nil
	}

	// XXX: TODO just verify one deep for now
	if _, err = r.VerifyHeader(chain, header); err != nil {
		return err
	}

	var parent BlockHeader
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.GetParentHash(), number-1)
	}
	if parent == nil || parent.GetNumber().Uint64() != number-1 || parent.Hash() != header.GetParentHash() {
		return ErrUnknownAncestor
	}

	return nil
}

func (r *EndorsmentProtocol) VerifyHeader(chain headerByNumberChainReader, header BlockHeader) (*SignedExtraData, error) {

	bigBlockNumber := header.GetNumber()
	if bigBlockNumber.Cmp(big0) == 0 {
		return nil, fmt.Errorf("RRR the genesis header cannot be verified by this method")
	}

	// Check the seal (extraData) format is correct and signed
	se, sealerID, pub, err := r.codec.DecodeHeaderSeal(header)
	if err != nil {
		return nil, err
	}
	sealerPub, err := r.codec.BytesToPublic(pub)
	if err != nil {
		return nil, err
	}

	// Check that the intent in the seal matches the block described by the
	// header
	if se.Intent.ChainID != r.genesisEx.ChainID {
		return se, fmt.Errorf(
			"rrr sealed intent invalid chainid: %s != genesis: %s",
			se.Intent.ChainID.Hex(), r.genesisEx.ChainID.Hex())
	}

	// Check that the round in the intent matches the block number
	if se.Intent.RoundNumber.Cmp(bigBlockNumber) != 0 {
		return se, fmt.Errorf(
			"rrr sealed intent invalid intent round number: %s != block number: %s",
			se.Intent.RoundNumber, bigBlockNumber)
	}

	// Ensure that the coinbase is valid
	if header.GetNonce() != emptyNonce {
		return se, fmt.Errorf("rrr nonce must be empty")
	}

	// mix digest - we don't assert anything about that

	// sealingNodeAddr := common.Address(sealerID.Address())

	// Check that the NodeID in the intent matches the sealer
	if sealerID != se.Intent.NodeID {
		return se, fmt.Errorf("rrr sealer node id mismatch: sealer=`%s' node=`%s'",
			sealerID.Hex(), se.Intent.NodeID.Hex())
	}

	// Check that the sealed parent hash from the intent matches the parent
	// hash on the header.
	if se.Intent.ParentHash != header.GetParentHash() {
		return se, fmt.Errorf("rrr parent mismatch: sealed=`%s' header=`%s'",
			hex.EncodeToString(se.Intent.ParentHash[:]),
			Hash(header.GetParentHash()).Hex())
	}

	// Check that the sealed tx root from the intent matches the tx root in the
	// header.
	if se.Intent.TxHash != header.GetTxHash() {
		return se, fmt.Errorf("rrr txhash mismatch: sealed=`%s' header=`%s'",
			Hash(se.Intent.TxHash).Hex(), Hash(header.GetTxHash()).Hex())
	}

	// Verify the seed VRF result.
	blockNumber := bigBlockNumber.Uint64()

	// The input (or alpha) is from the block at the head of the stable prefix
	// (or the genesis)
	alpha := r.genesisEx.ChainInit.Seed
	if r.config.StablePrefixDepth < blockNumber {
		stableHeader := chain.GetHeaderByNumber(blockNumber - r.config.StablePrefixDepth)
		if stableHeader == nil {
			return nil, fmt.Errorf("block at stablePrefixDepth not found: %d - %d", blockNumber, r.config.StablePrefixDepth)
		}
		se, _, _, err := r.codec.DecodeHeaderSeal(stableHeader)
		if err != nil {
			return nil, fmt.Errorf("failed decoding stable header seal: %v", err)
		}
		alpha = se.Seed
	}

	// The beta, pi (seed, proof) is on this block header
	beta, err := r.vrf.Verify(sealerPub, alpha, se.Proof)
	if err != nil {
		return nil, fmt.Errorf("VRF Verify failed: %v", err)
	}
	if !bytes.Equal(se.Seed, beta) {
		return nil, fmt.Errorf(
			"VRF Verify failed. seed doesn't match proof: %v != %v",
			hex.EncodeToString(se.Seed), hex.EncodeToString(beta))
	}

	// Check all the endorsements. First check the intrinsic validity

	intentHash, err := r.codec.HashIntent(&se.Intent)
	if err != nil {
		return se, err
	}

	for _, end := range se.Confirm {
		// Check the endorsers ChainID
		if end.ChainID != r.genesisEx.ChainID {
			return se, fmt.Errorf("rrr endorsment chainid invalid: `%s'", end.IntentHash.Hex())
		}

		// Check that the intent hash signed by the endorser matches the intent
		// sealed in the block header by the leader
		if end.IntentHash != intentHash {
			return se, fmt.Errorf("rrr endorsment intent hash mismatch: sealed=`%s' endorsed=`%s'",
				intentHash.Hex(), end.IntentHash.Hex())
		}
	}
	return se, nil
}
