package tools_test

// Tests for go-rrr/consensus/rrr

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/RobustRoundRobin/go-rrr/consensus/rrr"
	"github.com/RobustRoundRobin/go-rrr/secp256k1suite"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rrrExtraVanity = 32
)

var (
	dummySeed  = []byte{0, 1, 2, 3, 4, 5, 6, 7}
	dummyProof = []byte{0, 1, 2, 3, 4, 5, 6, 7}
	bigOne     = new(big.Int).SetInt64(1)
)

func makeTimeStamp(t *testing.T, sec int64, nsec int64) []byte {
	ts := time.Unix(sec, nsec)
	b, err := ts.MarshalBinary()
	require.Nil(t, err)
	return b
}

func TestDecodeGenesisActivity(t *testing.T) {

	codec := NewCodec()

	assert := assert.New(t)
	require := require.New(t)

	var err error
	keys := requireGenerateKeys(t, 3)
	ge := requireMakeGenesisExtra(t,
		keys[0], dummySeed, dummyProof, identitiesFromKeys(keys...), keys)
	assert.NoError(err)

	extra, err := codec.EncodeHashGenesisExtraData(ge)
	require.NoError(err)

	genesis := makeBlockHeader(withExtra(extra))

	a := &rrr.BlockActivity{}
	codec.DecodeBlockActivity(a, ge.ChainID, genesis)

	assert.Len(a.Enrol, 3, "missing enrolments")
}

func TestDecodeActivity(t *testing.T) {

	assert := assert.New(t)
	require := require.New(t)
	codec := NewCodec()

	keys := requireGenerateKeys(t, 3)
	ge := requireMakeGenesisExtra(t,
		keys[0], dummySeed, dummyProof, identitiesFromKeys(keys...), keys)

	data, err := codec.EncodeHashGenesisExtraData(ge)
	require.NoError(err)
	genesis := makeBlockHeader(withExtra(data))

	intent := fillIntent(nil, ge.ChainID, keys[0], genesis, big.NewInt(1), 0)

	se1 := requireMakeSignedEndorsement(t, ge.ChainID, keys[1], intent)
	se2 := requireMakeSignedEndorsement(t, ge.ChainID, keys[2], intent)

	_, data = requireMakeSignedExtraData(t,
		keys[0], makeTimeStamp(t, 0, 0),
		intent, []*rrr.SignedEndorsement{se1, se2}, []byte{8, 9, 10, 11, 12, 13, 14, 15})

	block1 := makeBlockHeader(withNumber(1), withSeal(data))
	a := &rrr.BlockActivity{}
	codec.DecodeBlockActivity(a, ge.ChainID, block1)

	assert.Len(a.Confirm, 2, "missing confirmations")
}

func NewLogger(l log.Logger) *Logger {

	if l == nil {
		l = log.New()
	}
	l.SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(false)))
	return &Logger{L: l}
}

func NewActiveSelection(codec *rrr.CipherCodec, logger rrr.Logger) rrr.ActiveSelection {
	a := rrr.NewActiveSelection(codec, rrr.Hash{1, 2, 3}, logger)
	return a
}

// TestAccumulateGenesisActivity tests that the order of enrolments
// in the gensis block match the order produced by ActiveSelection from the
// genesis block
func TestAccumulateGenesisActivity(t *testing.T) {

	require := require.New(t)
	assert := assert.New(t)

	tActive := uint64(10)
	numIdents := 12

	net := newNetwork(t, numIdents)
	ch := newChain(net.genesis)

	a := NewActiveSelection(NewCodec(), NewLogger(nil))

	a.Reset(tActive, net.genesis)

	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentHeader())

	require.NoError(err)
	assert.Equal(a.NumActive(), numIdents, "missing active from selection")

	// For the genesis block, the age ordering should exactly match the
	// enrolment order. And the identity that signed the genesis block should be
	// the youngest - as it is considered more recently active than any identity
	// it enrols in the block it seals.
	order := make([]int, numIdents)
	for i := 0; i < numIdents; i++ {
		order[numIdents-i-1] = i
	}

	net.requireOrder(t, a, order)
}

// TestFirstAccumulate tests the accumulation of activity from the first
// consensus block (the block after genesis)
func TestFirstAccumulate(t *testing.T) {

	require := require.New(t)
	assert := assert.New(t)

	tActive := uint64(10)
	net := newNetwork(t, 3)
	ch := newChain(net.genesis)
	ch.Extend(net, 0, 1, 2)

	a := NewActiveSelection(NewCodec(), NewLogger(nil))
	a.Reset(tActive, net.genesis)

	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentHeader())

	require.NoError(err)
	assert.Equal(a.NumKnown(), 3, "missing active from aged")
	assert.Equal(a.NumActive(), 3, "missing active from selection")
	assert.Equal(a.NumIdle(), 0, "idle identities found")

	// the youngest identity should be at the front and should be the id=0
	id, ok := net.nodeID2id[a.YoungestNodeID()]
	require.True(ok)
	assert.Equal(id, 0)

}

// TestAccumulateTwice tests that the order is stable (and correct) if the same
// identity is encountered twice. The first encounter of the identity in an
// accumulation determines its age. Any subsequent enconter should not change
// it.
func TestAccumulateTwice(t *testing.T) {
	require := require.New(t)

	tActive := uint64(10)
	numIdents := 12

	net := newNetwork(t, numIdents)
	ch := newChain(net.genesis)

	a := NewActiveSelection(NewCodec(), NewLogger(nil))
	a.Reset(tActive, net.genesis)

	// Establish the intial ordering from the genesis block.
	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentHeader())
	require.NoError(err)

	net.requireOrder(t, a, []int{11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0})

	// Make 3 blocks. The first and the last will be sealed by the same identity.

	ch.Extend(net, 1, 2, 3, 4) // sealer, ...endorsers.
	// Imagining the rounds progress as expected, 2 should seal next
	ch.Extend(net, 2, 3, 4, 5)
	// Something very odd happened and 1 seals the next block (in reality this
	// implies a lot of failed attempts and un reachable nodes). Lets make the
	// endorsers the same too.
	ch.Extend(net, 1, 2, 3, 4)

	err = a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentHeader())
	require.NoError(err)

	// Note: only the sealer id's should move
	net.requireOrder(t, a, []int{1, 2, 11, 10, 9, 8, 7, 6, 5, 4, 3, 0})
}

// TestBranchDetection tests that AccumulateActive spots forks and returns a
// specific error for that case.
func TestBranchDetection(t *testing.T) {
	require := require.New(t)

	logger := log.New()
	logger.SetHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(false)))

	tActive := uint64(10)
	numIdents := 12

	net := newNetwork(t, numIdents)
	ch := newChain(net.genesis)

	a := NewActiveSelection(NewCodec(), NewLogger(nil))
	a.Reset(tActive, net.genesis)

	// build a 4 block chain
	ch.Extend(net, 1, 2, 3, 4) // sealer, ...endorsers
	ch.Extend(net, 2, 3, 4, 5)
	ch.Extend(net, 3, 4, 5, 6)
	ch.Extend(net, 4, 5, 6, 7)

	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentHeader())
	require.NoError(err)

	// Make a fork from block 2
	intent := net.newIntent(5, ch.blocks[2], 0)
	confirm := net.endorseIntent(intent, 6, 7, 8)
	forkFirst := net.sealBlock(5, intent, confirm, dummySeed)
	ch.Add(forkFirst)
	// Now CurrentBlock will return the forked block so we can use extend
	ch.Extend(net, 6, 7, 8, 9)

	err = a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentHeader())
	require.True(errors.Is(err, rrr.ErrBranchDetected))
}

// TestShortActivityHorizon tests that the age order of the active selection is
// correct in the event that the activity horizon does not move all identities.
// As is the case when one or more identities are idle - idle means "not seen
// within Ta active". Also, except for the early stages of the chain, Ta
// (active) will be smaller than the block height and this covers that scenario
// too. Note that AccumulateActive does not explicitly identify idles - it
// leaves the unvisited items in the list in their last known possition.
// selectCandidatesAndEndorsers deals with pruning and moving to the idle pool.
func TestShortActityHorizon(t *testing.T) {
	require := require.New(t)

	logger := NewLogger(nil)

	tActive := uint64(5)
	numIdents := 12

	net := newNetwork(t, numIdents)
	ch := newChain(net.genesis)

	codec := NewCodec()
	a := NewActiveSelection(codec, logger)

	a.Reset(tActive, net.genesis)

	ch.Extend(net, 1, 2, 3, 4) // sealer, ...endorsers
	ch.Extend(net, 2, 3, 4, 5)
	ch.Extend(net, 3, 4, 5, 6)
	ch.Extend(net, 4, 5, 6, 7)

	err := a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentHeader())
	require.NoError(err)

	// We have exactly 5 blocks including the genesis. The genesis has activity
	// for all 12 identities.
	// order := []int{5, 6, 7, 8, 9, 10, 11, 0, 1, 2, 3, 4}
	order := []int{4, 3, 2, 1, 11, 10, 9, 8, 7, 6, 5, 0}
	net.requireOrder(t, a, order)

	// Add 7 more blocks
	ch.Extend(net, 5, 6, 7, 8)
	ch.Extend(net, 6, 7, 8, 9)
	ch.Extend(net, 7, 8, 9, 10)
	ch.Extend(net, 8, 9, 10, 11)
	ch.Extend(net, 9, 10, 11, 0)
	ch.Extend(net, 10, 11, 0, 1)
	ch.Extend(net, 11, 0, 1, 2)
	ch.Extend(net, 0, 1, 2, 3)

	err = a.AccumulateActive(
		net.ge.ChainID, tActive, ch, ch.CurrentHeader())
	require.NoError(err)

	// Now we expect the sealers of the most recent 5 to move, and everything
	// else to stay as it was. selectCandidatesAndEndorsers *skips* items that
	// are beyond the tActive horizon. When idles are fully implemented,
	// skipping will involve moving to the idle pool.

	order = []int{0, 11, 10, 9, 8, 4, 3, 2, 1, 7, 6, 5}
	net.requireOrder(t, a, order)
}

func (net *network) requireOrder(t *testing.T, a rrr.ActiveSelection, order []int) {

	nok := 0

	for cur, icur := rrr.NewActiveSelectionCursor(a).Front(), 0; cur != nil; cur, icur = cur.Next(), icur+1 {

		nodeID := cur.NodeID()

		ok := order[icur] == net.nodeID2id[nodeID]
		if ok {
			nok++
		}

		net.logger.Info(
			"activeItem", "ok", ok, "addr", nodeID.Address().HexShort(),
			"order", order[icur], "id", net.nodeID2id[nodeID], "position", icur)
	}
	require.Equal(t, nok, len(order))
}

// network represents a network of identities participating in RRR consensus
// for the purposes of the tests
type network struct {
	t      *testing.T
	logger rrr.Logger

	ge      *rrr.GenesisExtraData
	genesis rrr.BlockHeader

	// For clarity of testing, work with integer indices as id's
	id2key    map[int]*ecdsa.PrivateKey
	id2NodeID map[int]rrr.Hash
	nodeID2id map[rrr.Hash]int
	keys      []*ecdsa.PrivateKey
}

type chain struct {
	blocks []rrr.BlockHeader
	db     map[rrr.Hash]int
}

func newChain(genesis rrr.BlockHeader) *chain {
	ch := &chain{
		blocks: []rrr.BlockHeader{genesis},
		db:     make(map[rrr.Hash]int),
	}
	ch.db[ch.blocks[0].Hash()] = 0
	return ch
}

func (ch *chain) CurrentHeader() rrr.BlockHeader {
	return ch.blocks[len(ch.blocks)-1]
}

func (ch *chain) GetHeaderByHash(hash [32]byte) rrr.BlockHeader {
	if i, ok := ch.db[hash]; ok {
		return ch.blocks[i]
	}
	return nil
}

func (ch *chain) Extend(net *network, idSeal int, idConfirm ...int) rrr.BlockHeader {
	parent := ch.CurrentHeader()

	intent := net.newIntent(idSeal, parent, 0)
	confirm := net.endorseIntent(intent, idConfirm...)
	header := net.sealBlock(idSeal, intent, confirm, dummySeed)
	ch.Add(header)
	return header
}

// Add adds a block
func (ch *chain) Add(header rrr.BlockHeader) {
	ch.blocks = append(ch.blocks, header)
	ch.db[header.Hash()] = len(ch.blocks) - 1
}

func newNetwork(t *testing.T, numIdents int) *network {

	c := secp256k1suite.NewCipherSuite()
	codec := NewCodec()

	net := &network{
		t:         t,
		logger:    NewLogger(nil),
		keys:      requireGenerateKeys(t, numIdents),
		id2key:    make(map[int]*ecdsa.PrivateKey),
		id2NodeID: make(map[int]rrr.Hash),
		nodeID2id: make(map[rrr.Hash]int),
	}

	identities := identitiesFromKeys(net.keys...)
	for id, key := range net.keys {
		net.id2key[id] = key
		net.id2NodeID[id] = rrr.NodeIDFromPub(c, &key.PublicKey)
		net.nodeID2id[net.id2NodeID[id]] = id
	}

	net.ge = requireMakeGenesisExtra(t,
		net.keys[0], dummySeed, dummyProof,
		identities, net.keys)

	extra, err := codec.EncodeHashGenesisExtraData(net.ge)
	require.NoError(t, err)

	net.genesis = makeBlockHeader(withExtra(extra))

	return net
}

func (net *network) newIntent(
	idFrom int, parent rrr.BlockHeader) *rrr.Intent {
	key := net.id2key[idFrom]
	require.NotZero(net.t, key)

	roundNumber := big.NewInt(0)
	roundNumber.Add(parent.GetNumber(), bigOne)
	return fillIntent(
		nil, net.ge.ChainID, key, parent, roundNumber)
}

func (net *network) endorseIntent(
	intent *rrr.Intent, idBy ...int) []*rrr.SignedEndorsement {

	confirm := make([]*rrr.SignedEndorsement, len(idBy))
	for i, id := range idBy {
		key := net.id2key[id]
		require.NotZero(net.t, key)
		confirm[i] = requireMakeSignedEndorsement(net.t, net.ge.ChainID, key, intent)
	}
	return confirm
}

func (net *network) sealBlock(
	idSealer int, intent *rrr.Intent, confirm []*rrr.SignedEndorsement, seed []byte,
) rrr.BlockHeader {

	key := net.id2key[idSealer]
	require.NotZero(net.t, key)

	_, data := requireMakeSignedExtraData(
		net.t, key, makeTimeStamp(net.t, 0, 0), intent, confirm, dummySeed)

	return makeBlockHeader(
		withNumber(int64(intent.RoundNumber)),
		withParent(common.Hash(intent.ParentHash)),
		withSeal(data))
}

func requireMakeSignedExtraData(
	t *testing.T,
	sealer *ecdsa.PrivateKey,
	sealTime []byte, intent *rrr.Intent, confirm []*rrr.SignedEndorsement,
	seed []byte,
) (*rrr.SignedExtraData, []byte) {

	data := &rrr.SignedExtraData{
		ExtraData: rrr.ExtraData{
			ExtraHeader: rrr.ExtraHeader{
				SealTime: sealTime,
			},
			Intent:  *intent,
			Confirm: make([]rrr.Endorsement, len(confirm)),
		},
	}
	data.Intent.RoundNumber = intent.RoundNumber
	if seed != nil {
		copy(data.Seed, seed)
	}
	for i, c := range confirm {
		data.Confirm[i] = c.Endorsement
	}

	codec := NewCodec()
	seal, err := codec.EncodeSignExtraData(data, sealer)
	require.NoError(t, err)
	return data, seal
}

func requireMakeSignedEndorsement(
	t *testing.T,
	chainID rrr.Hash, endorser *ecdsa.PrivateKey, intent *rrr.Intent) *rrr.SignedEndorsement {

	c := secp256k1suite.NewCipherSuite()
	codec := NewCodec()

	h, err := codec.HashIntent(intent)
	require.NoError(t, err)

	se := &rrr.SignedEndorsement{
		Endorsement: rrr.Endorsement{
			ChainID:    chainID,
			IntentHash: h,
			EndorserID: rrr.NodeIDFromPub(c, &endorser.PublicKey),
		},
	}
	return se
}

func fillIntent(
	i *rrr.Intent,
	chainID rrr.Hash, proposer *ecdsa.PrivateKey,
	parent rrr.BlockHeader, roundNumber *big.Int) *rrr.Intent {

	c := secp256k1suite.NewCipherSuite()

	if i == nil {
		i = &rrr.Intent{}
	}

	i.ChainID = chainID
	i.NodeID = rrr.NodeIDFromPub(c, &proposer.PublicKey)
	i.RoundNumber = roundNumber.Uint64()
	i.ParentHash = rrr.Hash(parent.Hash())
	i.TxHash = rrr.Hash(parent.GetTxHash())
	return i
}

func requireMakeGenesisExtra(
	t *testing.T,
	key *ecdsa.PrivateKey,
	seed, proof []byte, identities []rrr.Hash, idKeys []*ecdsa.PrivateKey) *rrr.GenesisExtraData {

	c := secp256k1suite.NewCipherSuite()
	codec := NewCodec()

	initIdents, err := rrr.IdentInit(codec, key, nil, identities...)
	require.NoError(t, err)

	alphaContrib := map[rrr.Hash]rrr.Alpha{}
	for i, enrolment := range initIdents {

		// Just using the id hash as the contribution here for convenience

		sig, err := c.Sign(enrolment.ID[:], idKeys[i])
		require.NoError(t, err)
		require.Equal(t, len(sig), 65)
		a := rrr.Alpha{Contribution: enrolment.ID}
		copy(a.Sig[:], sig)
		alphaContrib[rrr.Hash(enrolment.ID)] = a
	}

	extra := &rrr.GenesisExtraData{}
	codec.PopulateChainInit(&extra.ChainInit, key, initIdents, alphaContrib)
	return extra
}

type headerOption func(h *types.Header)

func withNumber(n int64) headerOption {
	return func(h *types.Header) {
		h.Number = big.NewInt(n)
	}
}
func withExtra(extra []byte) headerOption {
	return func(h *types.Header) {
		h.Extra = nil
		if extra != nil {
			h.Extra = make([]byte, len(extra))
			copy(h.Extra[:], extra)
		}
	}
}

func withSeal(seal []byte) headerOption {
	return func(h *types.Header) {
		h.Extra = nil
		if seal != nil {
			h.Extra = make([]byte, rrrExtraVanity+len(seal))
			copy(h.Extra[rrrExtraVanity:], seal)
		}
	}
}

func withParent(parentHash [32]byte) headerOption {
	return func(h *types.Header) {
		copy(h.ParentHash[:], parentHash[:])
	}
}

func makeBlockHeader(opts ...headerOption) rrr.BlockHeader {

	header := &types.Header{
		Difficulty: big.NewInt(0),
		Number:     big.NewInt(0),
		GasLimit:   0,
		GasUsed:    0,
		Time:       0,
	}
	for _, opt := range opts {
		opt(header)
	}

	return NewBlockHeader(header)
}

func requireGenerateKeys(t *testing.T, count int) []*ecdsa.PrivateKey {

	var err error

	keys := make([]*ecdsa.PrivateKey, count)
	for i := 0; i < count; i++ {
		keys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
	}

	return keys
}

func identitiesFromKeys(keys ...*ecdsa.PrivateKey) []rrr.Hash {

	c := secp256k1suite.NewCipherSuite()
	nodeIDs := make([]rrr.Hash, len(keys))
	for i, key := range keys {
		nodeIDs[i] = rrr.NodeIDFromPub(c, &key.PublicKey)
	}
	return nodeIDs
}
