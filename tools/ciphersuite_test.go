package tools_test

// Tests for go-rrr/consensus/rrr

import (
	"github.com/RobustRoundRobin/go-rrr/consensus/rrr"
	"github.com/RobustRoundRobin/go-rrr/secp256k1suite"
	"github.com/ethereum/go-ethereum/rlp"
)

type BytesCodec struct{}

func (bc *BytesCodec) EncodeToBytes(val interface{}) ([]byte, error) {
	return rlp.EncodeToBytes(val)
}

func (bc *BytesCodec) DecodeBytes(b []byte, val interface{}) error {
	return rlp.DecodeBytes(b, val)
}

func NewCodec() *rrr.CipherCodec {
	return rrr.NewCodec(secp256k1suite.NewCipherSuite(), &BytesCodec{})
}
