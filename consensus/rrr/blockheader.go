package rrr

import "math/big"

type BlockHeader interface {
	Hash() [32]byte        // includes rrr seal
	HashForSeal() [32]byte // excludes rrr seal
	GetParentHash() [32]byte
	GetRoot() [32]byte
	GetTxHash() [32]byte
	GetNumber() *big.Int
	GetTime() uint64
	GetSeal() []byte
	GetNonce() [8]byte
}
