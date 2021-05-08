package tools_test

// Tests for go-rrr/consensus/rrr

// (C) Copyright 2021
// The Go RRR Authors
// SPDX-License-Identifier:

// XXX: TODO we will license this single file with the Unlicense so people are
// free to copy 'paste it without attribution.

import (
	"math/big"

	"github.com/RobustRoundRobin/go-rrr/consensus/rrr"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

const (
	// RRRExtraVanity is the lenght of the space BEFORE rrr's consensus data.
	// It's the space we leave for normal node vanity.
	RRRExtraVanity = 32
)

type BlockHeader struct {
	types.Header
}

func NewBlockHeader(h *types.Header) rrr.BlockHeader {
	return &BlockHeader{Header: *h}
}

func (h *BlockHeader) Hash() [32]byte {
	return h.Header.Hash()
}

func sealHash(header *types.Header) [32]byte {

	hasher := sha3.NewLegacyKeccak256()

	h := [32]byte{}

	err := rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:RRRExtraVanity],
	})
	if err != nil {
		panic("can't encode for sealHash: " + err.Error())
	}
	hasher.Sum(h[:0])
	return h
}

func (h *BlockHeader) HashForSeal() [32]byte {
	return sealHash(&h.Header)
}

func (h *BlockHeader) GetParentHash() [32]byte {
	return rrr.Hash(h.ParentHash)
}

func (h *BlockHeader) GetRoot() [32]byte {
	return h.Root
}

func (h *BlockHeader) GetTxHash() [32]byte {
	return h.TxHash
}

func (h *BlockHeader) GetNumber() *big.Int {
	return h.Number
}

func (h *BlockHeader) GetTime() uint64 {
	return h.Time
}

func (h *BlockHeader) GetSeal() []byte {
	return h.Extra[RRRExtraVanity:]
}

func (h *BlockHeader) GetNonce() [8]byte {
	return h.Nonce
}
