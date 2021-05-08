package tools_test

// Tests for go-rrr/consensus/rrr
import (
	"testing"

	"github.com/RobustRoundRobin/go-rrr/consensus/rrr"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	ecvrf "github.com/vechain/go-ecvrf"
)

func TestIntentDecodeSigned(t *testing.T) {
	require := require.New(t)

	k, err := crypto.GenerateKey()
	require.Nil(err)

	i := &rrr.SignedIntent{
		Intent: rrr.Intent{
			ChainID: rrr.Hash{1, 2}, NodeID: rrr.Hash{3, 4}, ParentHash: rrr.Hash{5, 6}},
	}
	codec := NewCodec()

	raw, err := codec.EncodeSignIntent(i, k)
	iv := &rrr.SignedIntent{}
	_, err = codec.DecodeSignedIntent(iv, raw)
	require.Nil(err)
}

// TestVRF is just an integration test to show we can build and use the dep
func TestVRF(t *testing.T) {
	require := require.New(t)

	sk, err := crypto.GenerateKey()
	require.Nil(err)

	alpha := "Hello RRR"

	vrf := ecvrf.NewSecp256k1Sha256Tai()

	beta, pi, err := vrf.Prove(sk, []byte(alpha))
	require.Nil(err)

	beta2, err := vrf.Verify(&sk.PublicKey, []byte(alpha), pi)
	require.Nil(err)
	require.Equal(beta, beta2)
}
