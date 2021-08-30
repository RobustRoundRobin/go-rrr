package rrr

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

var (
	ErrIntentAndConfirmPhaseToLarge = errors.New("intent + confirm phase can not be longer than the round")
	ErrIncompatibleChainReader      = errors.New("chainreader missing required interfaces for RRR")
	ErrNoGenesisHeader              = errors.New("failed to get genesis header")
	ErrNotLeaderCandidate           = errors.New("expected to be leader candidate")
	ErrEngineStopped                = errors.New("consensus not running")
	ErrRMsgInvalidCode              = errors.New("recevived RMsg with invalid code")

	// Difficulty is the measure of 'how hard' it is to extend the chain. For
	// PoA, and RRR in particular, this is just an indicator of whose turn it
	// is. Essentially it is always 'harder' for the peers that are currently
	// leader candidates - as they must wait for endorsements. The peers whose
	// turn it is to endorse don't actually publish blocks at all, but we have
	// an endorser difficulty to make sure any transitory local data makes
	// sense.
	difficultyForCandidate = big.NewInt(2)
	difficultyForEndorser  = big.NewInt(1)

	// message de-duplication
	lruPeers           = 100 + 6*2
	lruMessages        = 1024
	lruHeaderSigner    = 20
	lruVerifiedHeaders = 20
)

// EngNewChainHead notifies the run loop of a NewChainHead event.
type EngNewChainHead struct {
	BlockHeader BlockHeader
}

type EngineChainReader interface {
	CurrentHeader() BlockHeader
	GetHeaderByNumber(number uint64) BlockHeader
	GetHeaderByHash(hash [32]byte) BlockHeader
}

type Peer interface {

	// SendConsensus sends a consensus message to this peer
	SendConsensus(data interface{}) error
}

type PeerFinder interface {
	FindPeers(map[Address]bool) map[Address]Peer
}

// The engine supplies these so that the roundstate can call out to the network at the right points.
type Broadcaster interface {
	PeerFinder
	// Broadcast self, peers, msg
	Broadcast(Address, map[Address]Peer, []byte) error

	// SendSignedEndorsement ...
	SendSignedEndorsement(intenderAddr Address, et *EngSignedIntent) error
}

// Engine implements consensus.Engine using Robust Round Robin consensus
// https://arxiv.org/abs/1804.07391
type Engine struct {
	*EndorsmentProtocol

	// Don't change these while the engine is running
	privateKey *ecdsa.PrivateKey

	// If set, called when candidates fail there round attempt. It is expected
	// to check for clock drift and take appropriate action (ie log a warning)
	clockChecker func()

	peerFinder PeerFinder

	// must be held for any interaction with ARCCache *Messages members
	messagingMu sync.RWMutex

	// Track which messages we have sent or received. We do not re-gossip
	// these. (IBFT calls these 'recentMessages'). We maintain a 2 level arc
	// here, for each of lruPeers we have an lru of recent messages.
	peerMessages *lru.ARCCache

	// Track which messages we have posted on our local processing queue. We do
	// not re-broadcast these. We do not re post these locally.
	selfMessages *lru.ARCCache

	headerSignerCache   *lru.ARCCache
	verifiedHeaderCache *lru.ARCCache

	runningMu sync.RWMutex // hold read lock if checking 'runningCh is nil'
	runningWG sync.WaitGroup

	// runningCh is passed as the input channel to the engine run() method.
	// The run method assumes the ownership of all values sent to this channel.
	// Handles all of the  eng* types and core.ChainHeadEvent
	runningCh chan interface{}
}

func (e *Engine) RunLock() {
	e.runningMu.Lock()
}

func (e *Engine) RunUnlock() {
	e.runningMu.Unlock()
}

func (e *Engine) NodeID() Hash {
	return e.nodeID
}

// ChainID is the chain identifier. Will return the zero hash until Start is
// called.
func (e *Engine) ChainID() Hash {
	return e.genesisEx.ChainID
}

// NodeAddress returns the node address
func (e *Engine) NodeAddress() Address {
	return e.nodeAddr
}

// NodePublic returns the marshaled public key. (uncompressed form specified in section 4.3.6 of ANSI X9.62)
func (e *Engine) NodePublic() []byte {
	return PubMarshal(e.codec.c, &e.privateKey.PublicKey)
}

// IsRunning returns true if the engine is still running
func (e *Engine) IsRunning() bool {
	e.runningMu.RLock()
	defer e.runningMu.RUnlock()
	return e.runningCh != nil
}

func (e *Engine) IsEnrolmentPending(nodeID [32]byte) bool {
	return e.EndorsmentProtocol.IsEnrolmentPending(nodeID)
}

type EngineOption func(e *Engine)

func WithClockCheck(checker func()) EngineOption {
	return func(e *Engine) {
		e.clockChecker = checker
	}
}

// NewEngine a new instance of the rrr consensus engine. Assumes the provided
// engine instance is new.
func NewEngine(
	config *Config, codec *CipherCodec,
	privateKey *ecdsa.PrivateKey, logger Logger, opts ...EngineOption) (*Engine, error) {

	if (config.IntentPhase + config.ConfirmPhase) >= config.RoundLength {
		return nil, fmt.Errorf(
			"i=%v, c=%v, round=%v: %w",
			config.IntentPhase, config.ConfirmPhase, config.RoundLength, ErrIntentAndConfirmPhaseToLarge)
	}

	// Only get err from NewRC if zize requested is <=0
	peerMessages, err := lru.NewARC(lruPeers)
	if err != nil {
		return nil, err
	}
	selfMessages, err := lru.NewARC(lruMessages)
	if err != nil {
		return nil, err
	}

	headerSignerCache, err := lru.NewARC(lruHeaderSigner)
	if err != nil {
		return nil, err
	}
	verifiedHeaderCache, err := lru.NewARC(lruVerifiedHeaders)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		privateKey:          privateKey,
		EndorsmentProtocol:  NewRoundState(codec, privateKey, config, logger),
		peerMessages:        peerMessages,
		selfMessages:        selfMessages,
		headerSignerCache:   headerSignerCache,
		verifiedHeaderCache: verifiedHeaderCache,
	}

	for _, o := range opts {
		o(e)
	}

	return e, nil
}

// Start the consensus protocol. To allow for atomic cleanup, the caller
// provided withLock is invoked as soon as the lock is aquired. Note that
// withLock is *always* called if it is not nil - regardless of whether the
// engine is already started.
func (e *Engine) Start(
	chain EngineChainReader, withLock WithLock) error {

	e.runningMu.Lock()
	defer e.runningMu.Unlock()

	if withLock != nil {
		withLock()
	}

	if e.runningCh != nil {
		return nil
	}

	// IF we are starting for the first time or the active selection has been
	// thrown away, this will re initialise it. else we are re-starting,
	// and accumulateActive will catch up as appropriate for the new head
	if err := e.PrimeActiveSelection(chain); err != nil {
		return err
	}

	e.runningCh = make(chan interface{})
	go e.run(chain, e.runningCh)

	return nil
}

type WithLock func()

// Stop stops the engine. To allow for atomic cleanup, the caller provided
// withLock is invoked as soon as the lock is aquired.
func (e *Engine) Stop(withLock WithLock) {

	e.runningMu.Lock()

	if withLock != nil {
		withLock()
	}

	if e.runningCh != nil {

		close(e.runningCh)
		e.runningCh = nil
		e.runningMu.Unlock()

		e.runningWG.Wait()

	} else {
		e.runningMu.Unlock()
	}
}

func (e *Engine) run(chain EngineChainReader, ch <-chan interface{}) {

	defer e.runningWG.Done()
	e.runningWG.Add(1)

	// Sort out the initial state and kick of the ticker.
	e.StartRounds(e, chain)

	// Endorsed leader candidates will broadcast the new block at the end of
	// the round according to their tickers. We reset the ticker each time we
	// see a new block confirmed. This will cause all participants to loosely
	// align on the same time window for each round. In the absence of
	// sufficient endorsments to produce a block, each leader candidate will
	// simply re-broadcast their current intent.

	for {
		select {

		case i, ok := <-ch:

			if !ok {
				e.logger.Info("RRR run - input channel closed")
				return
			}

			switch et := i.(type) {

			case *EngNewChainHead:

				e.NewChainHead(e, chain, et.BlockHeader)

			// new work from the miner
			case *EngSealTask:

				e.NewSealTask(e, et)

			// Consensus protocol: a leaders signed intent to produce a block
			case *EngSignedIntent:

				e.NewSignedIntent(et)

			// Consensus protocol: endorsers responding to a leaders intent
			case *EngSignedEndorsement:

				e.NewSignedEndorsement(et)

			// enrolment of new identities post genesis. XXX: TODO make this (at
			// least) respect --permissioned and permissioned-nodes.json. Longer
			// term we would like to consider identity mining as descibed in the
			// paper.
			case *EngEnrolIdentity:

				e.QueueEnrolment(et)

			default:
				e.logger.Info("rrr engine.run received unknown type", "v", i)
			}

		case <-e.T.Ticker.C:

			e.PhaseTick(e, chain)
		}
	}
}

// HandleMsg handles a message from peer and deals with gossiping consensus
// messages where necessary.
func (e *Engine) HandleMsg(peerAddr Address, msg []byte) (bool, error) {

	var err error

	msgHash := Keccak256Hash(e.codec.c, msg)

	rmsg := RMsg{}
	if err = e.codec.DecodeBytes(msg, &rmsg); err != nil {
		return true, err
	}

	e.logger.Trace(
		"RRR HandleMsg", "#msg", msgHash.Hex(),
		"#raw", e.codec.Keccak256Hash(rmsg.Raw).Hex())

	if seen := e.updateInboundMsgTracking(peerAddr, msgHash); seen {
		e.logger.Trace("RRR HandleMsg - ignoring previously seen")
		return true, nil
	}

	// If its a normal direct consensus message, handle and return
	if rmsg.Round == 0 {
		return true, e.handleMsg(peerAddr, rmsg)
	}

	// Ok this is a gossiped consensus message

	if rmsg.Round != e.Number {
		e.logger.Debug("RRR HandleMsg - ignoring gossip for different round", "r", e.Number, "rmsg.Round", rmsg.Round)
		return true, nil
	}

	// For gossiped messages we also need to track the hash of the Raw. Because
	// we change the To list in the envelop as we proprage the gossip.
	// Terminating the gossip requires that we ignore messages we have seen
	// before.
	rawHash := Keccak256Hash(e.codec.c, rmsg.Raw)
	if seen := e.updateInboundMsgTracking(peerAddr, rawHash); seen {
		e.logger.Trace("RRR HandleMsg - ignoring previously seen gossip", "r", e.Number, "#raw", rawHash.Hex())
		return true, nil
	}

	// For each recipient we have a direct peer connection, send it directly. If
	// any are left continue the gossip. If none are left there is no point
	// continuing the gossip - we know all recipients have recieved it at least
	// once if To is empty.
	var handleErr error
	var to []Address
	for _, addr := range rmsg.To {

		// Handle the message if the local node is a recipient
		if addr == e.nodeAddr {
			e.logger.Trace("RRR HandleMsg - gossip delivery", "r", e.Number, "to", addr.Hex(), "#raw", rawHash.Hex())
			handleErr = e.handleMsg(peerAddr, rmsg)
			continue
		}

		// Forward directly to any recipient we have a peer connection for.
		if p, ok := e.onlineEndorsers[addr]; ok {
			e.peerSend(p, addr, msg, msgHash)
			continue
		}

		// collect any remainders
		to = append(to, addr)
	}

	// if there are any gossip recipients left, continue the gossip
	if len(to) > 0 {
		err = e.continueEndorserGossip(e, rmsg, to)
		if err != nil {
			e.logger.Trace("RRR HandleMsg - continueEndorserGossip", "r", e.Number, "err", err)
		}
	}

	return true, handleErr
}

// handleMsg handles a message from peer that is intended for the local node.
func (e *Engine) handleMsg(peerAddr Address, rmsg RMsg) error {

	var err error

	switch rmsg.Code {
	case RMsgIntent:

		e.logger.Trace("RRR HandleMsg - RMSgIntent")

		si := &EngSignedIntent{}

		if si.Pub, err = e.codec.DecodeSignedIntent(&si.SignedIntent, rmsg.Raw); err != nil {
			e.logger.Debug("RRR Intent decodeverify failed", "err", err)
			return err
		}

		e.logger.Trace("RRR handleMsg - RMsgIntent", "for", si.Intent.NodeID.Address().Hex(), "end", e.nodeAddr.Hex())
		if !e.PostIfRunning(si) {
			e.logger.Info("RRR Intent engine not running")
		}

		return nil

	case RMsgConfirm:

		e.logger.Trace("RRR HandleMsg - RMsgConfirm")
		sc := &EngSignedEndorsement{}

		if sc.Pub, err = e.codec.DecodeSignedEndorsement(
			&sc.SignedEndorsement, rmsg.Raw); err != nil {

			e.logger.Info("RRR RMsgConfirm decodeverify failed", "err", err)
			return err
		}
		e.logger.Trace("RRR handleMsg - RMsgConfirm", "for", e.nodeAddr.Hex(), "from", sc.EndorserID.Address().Hex())

		if !e.PostIfRunning(sc) {
			e.logger.Info("RRR handleMsg - RMsgConfirm failed to post", "for", e.nodeAddr.Hex())
		}
		return nil

	case RMsgEnrol:

		// Note: this is an enrolment request from another node. We support
		// this so that idled leaders can automaticaly request renrol without
		// going through the rpc. We will need to subjecti it to the same
		// permissioning that we apply to enrolments coming from the rpc.
		e.logger.Trace("RRR HandleMsg - post EngEnrolIdentity")
		ei := EngEnrolIdentity{}
		if err = e.codec.DecodeBytes(rmsg.Raw, &ei); err != nil {
			e.logger.Debug("RRR MsgEnrol decode EngEnrolIdentity failed", "err", err)
			return err
		}

		e.PostIfRunning(&ei)
		return nil

	default:
		return ErrRMsgInvalidCode
	}
}

func (e *Engine) FindPeers(
	peers map[Address]bool) map[Address]Peer {

	return e.peerFinder.FindPeers(peers)
}

// Send the message to the peer - if its hash is not in the ARU cache for the
// peer
func (e *Engine) Send(peerAddr Address, rmsg RMsg) error {

	peers := e.peerFinder.FindPeers(map[Address]bool{peerAddr: true})
	if len(peers) != 1 || peers[peerAddr] == nil {

		// Not directly connected, have to gossip

		rmsg.Round = e.Number
		rmsg.To = []Address{peerAddr}
		e.logger.Debug("RRR Send - via gossip", "r", e.Number, "to", peerAddr)
		e.initiateEndorserGossip(e, rmsg)
		return nil
	}

	e.logger.Trace("RRR Send - direct")
	msg, err := e.codec.EncodeToBytes(rmsg)
	if err != nil {
		e.logger.Info("RRR Send encoding rmsg", "err", err)
		return err
	}
	msgHash := e.codec.Keccak256Hash(msg)

	// directly connected
	return e.peerSend(peers[peerAddr], peerAddr, msg, msgHash)
}

func (e *Engine) peerSend(
	peer Peer, peerAddr Address, msg []byte, msgHash Hash,
) error {

	e.messagingMu.Lock()
	defer e.messagingMu.Unlock()

	var msgs *lru.ARCCache

	if i, ok := e.peerMessages.Get(peerAddr); ok {
		msgs = i.(*lru.ARCCache) // panic if we have put the wrong type in the cache
		if _, ok := msgs.Get(msgHash); ok {
			// have already sent the message to, or received it from, this peer
			return nil
		}
	} else {
		msgs, _ = lru.NewARC(lruMessages)
	}

	msgs.Add(msgHash, true)
	e.peerMessages.Add(peerAddr, msgs)

	e.logger.Trace(
		"RRR peerSend - sending", "hash", msgHash.Hex(),
		"safe-hash", e.codec.Keccak256Hash(msg).Hex())

	// Send will error imediately on encoding problems. But otherwise it
	// will block until the receiver consumes the message or the send times
	// out. So we can not sensibly collect errors.

	go func() {
		if err := peer.SendConsensus(msg); err != nil {
			e.logger.Info("RRR peerSend - SendConsensus", "err", err)
		}
	}()
	return nil
}

// Broadcast the message to the provided peers, skipping self. If we have
// previously sent the message to a peer, it is not resent.
func (e *Engine) Broadcast(self Address, peers map[Address]Peer, msg []byte) error {

	msgHash := e.codec.Keccak256Hash(msg)

	for peerAddr, peer := range peers {

		if peerAddr == self {
			e.logger.Trace("RRR Broadcast - skipping self")
			continue
		}

		if err := e.peerSend(peer, peerAddr, msg, msgHash); err != nil {
			e.logger.Info("RRR Broadcast - error sending msg", "err", err, "peer", peerAddr)
		}
	}
	return nil
}

// SendSignedEndorsement sends a signed (endorsed) intent back to the intender
func (e *Engine) SendSignedEndorsement(intenderAddr Address, et *EngSignedIntent) error {

	c := &SignedEndorsement{
		Endorsement: Endorsement{
			ChainID:    e.genesisEx.ChainID,
			EndorserID: e.nodeID,
		},
	}

	var err error
	c.IntentHash, err = e.codec.HashIntent(&et.SignedIntent.Intent)
	if err != nil {
		return err
	}

	rmsg := RMsg{Code: RMsgConfirm}

	rmsg.Raw, err = e.codec.EncodeSignEndorsement(c, e.privateKey)
	if err != nil {
		e.logger.Info("RRR encoding SignedEndorsement", "err", err.Error())
		return err
	}

	e.logger.Debug("RRR sending confirmation",
		"candidate", et.SignedIntent.NodeID.Hex(),
		"endorser", e.nodeID.Hex())

	// find the peer candidate
	return e.Send(intenderAddr, rmsg)
}

func (e *Engine) Seal(blockHeader BlockHeader, sealCommitter SealCommitter) error {

	if !e.IsRunning() {
		return fmt.Errorf("RRR Seal: %w", ErrEngineStopped)
	}

	st := &EngSealTask{
		BlockHeader: blockHeader,
		Committer:   sealCommitter,
	}

	// Note: in ethhash, this is where the PoW happens
	if !e.PostIfRunning(st) {
		return fmt.Errorf("RRR Seal: %w", ErrEngineStopped)
	}

	return nil
}

func (e *Engine) PostIfRunning(i interface{}) bool {
	e.runningMu.Lock()
	defer e.runningMu.Unlock()
	if e.runningCh == nil {
		e.logger.Debug("RRR PostIfRunning - engine not running")
		return false
	}

	e.runningCh <- i
	return true
}

// updateInboundMsgTracking updates the tracking of messages inbound from peers
func (e *Engine) updateInboundMsgTracking(peerAddr Address, hash Hash) bool {

	// keep track of messages seen from this peer recently
	e.messagingMu.Lock()
	defer e.messagingMu.Unlock()

	var msgs *lru.ARCCache
	if i, ok := e.peerMessages.Get(peerAddr); ok {
		msgs, _ = i.(*lru.ARCCache)
	} else {
		msgs, _ = lru.NewARC(lruMessages)
		e.peerMessages.Add(peerAddr, msgs)
	}
	msgs.Add(hash, true)

	// If we have seen this message, do not handle it again.
	var seen bool
	if _, seen = e.selfMessages.Get(hash); !seen {
		e.selfMessages.Add(hash, true)
	}
	return seen
}

// SetBroadcaster implements consensus.Handler.SetBroadcaster
// Which, for the quorum fork, is called by eth/handler.go NewProtocolManager
func (e *Engine) SetPeerFinder(f PeerFinder) {
	e.peerFinder = f
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have. For rrr this is just the round number
func (e *Engine) CalcDifficulty(chain interface{}, time uint64, parent BlockHeader) *big.Int {
	e.logger.Trace("RRR CalcDifficulty")
	return e.EndorsmentProtocol.CalcDifficulty(e.nodeAddr)
}

func (e *Engine) VerifySeal(chain VerifyBranchChainReader, header BlockHeader) error {

	if _, err := e.EndorsmentProtocol.VerifyHeader(chain, header); err != nil {
		return err
	}
	return nil
}

func (e *Engine) VerifyHeader(chain headerByHashChainReader, header BlockHeader) error {

	h := header.Hash()

	if v, ok := e.verifiedHeaderCache.Get(h); ok {
		return v.(error)
	}
	_, err := e.EndorsmentProtocol.VerifyHeader(chain, header)

	e.verifiedHeaderCache.Add(h, err)
	return err
}

func (e *Engine) VerifyBranchHeaders(
	chain VerifyBranchChainReader, header BlockHeader, parents []BlockHeader) error {
	return e.EndorsmentProtocol.VerifyBranchHeaders(chain, header, parents)
}

// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *Engine) Author(header BlockHeader) (Address, error) {

	return e.headerSigner(header)
}

func (e *Engine) headerSigner(header BlockHeader) (Address, error) {

	h := header.Hash()
	if addr, ok := e.headerSignerCache.Get(h); ok {
		return addr.(Address), nil
	}

	_, sealerID, _, err := e.codec.DecodeHeaderSeal(header)
	if err != nil {
		return Address{}, err
	}

	sealingNodeAddr := sealerID.Address()

	e.headerSignerCache.Add(h, sealingNodeAddr)

	return sealingNodeAddr, nil

}
