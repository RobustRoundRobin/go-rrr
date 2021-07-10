package tools_test

// Tests for go-rrr/consensus/rrr
import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/RobustRoundRobin/go-rrr/consensus/rrr"
)

func TestRoundTripChainID(t *testing.T) {

	var err error

	require := require.New(t)

	// Test that the chainid, and hence the encoding, is stable when round
	// triped through multiple encode / decode / encode operations

	extra1 := &rrr.GenesisExtraData{
		ChainInit: rrr.ChainInit{
			ExtraHeader: rrr.ExtraHeader{
				Seed:  []byte{0, 1, 2, 3},
				Proof: []byte{4, 5, 6, 7},
				Enrol: []rrr.Enrolment{{Q: rrr.Quote{8, 9}, U: rrr.Hash{10, 11}}},
			},
		},
	}

	codec := NewCodec()

	b, err := codec.EncodeHashGenesisExtraData(extra1)
	require.Nil(err)

	extra2 := &rrr.GenesisExtraData{}
	err = codec.DecodeGenesisExtra(b, extra2)
	require.Nil(err)

	b, err = codec.EncodeHashGenesisExtraData(extra2)
	require.Nil(err)

	extra3 := &rrr.GenesisExtraData{}
	err = codec.DecodeGenesisExtra(b, extra3)
	require.Nil(err)

	require.Equal(extra3.ChainID, extra2.ChainID, "extra data encoding  of chainid is incorrect")
	require.Equal(extra1.Enrol[0], extra2.Enrol[0])
	require.Equal(extra1.Enrol[0], extra3.Enrol[0])
}
