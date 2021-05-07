package rrr

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

var (
	ErrIncompatibleChainReader = errors.New("chainreader missing required interfaces for RRR")
	ErrNoGenesisHeader         = errors.New("failed to get genesis header")
	ErrNotLeaderCandidate      = errors.New("expected to be leader candidate")
	ErrEngineStopped           = errors.New("consensus not running")
	ErrRMsgInvalidCode         = errors.New("recevived RMsg with invalid code")

	bigOne = big.NewInt(1)

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
	lruPeers    = 100 + 6*2
	lruMessages = 1024
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

	// ConsensusMsg sends a consensus message to this peer
	ConsensusMsg(data interface{}) error
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
	codec *CipherCodec

	// Don't change these while the engine is running
	config     *Config
	privateKey *ecdsa.PrivateKey
	logger     Logger

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

	runningMu sync.RWMutex // hold read lock if checking 'runningCh is nil'
	runningWG sync.WaitGroup

	// runningCh is passed as the input channel to the engine run() method.
	// The run method assumes the ownership of all values sent to this channel.
	// Handles all of the  eng* types and core.ChainHeadEvent
	runningCh chan interface{}

	r *EndorsmentProtocol
}

func (e *Engine) RunLock() {
	e.runningMu.Lock()
}

func (e *Engine) RunUnlock() {
	e.runningMu.Unlock()
}

func (e *Engine) NodeID() Hash {
	return e.r.nodeID
}

// ChainID is the chain identifier. Will return the zero hash until Start is
// called.
func (e *Engine) ChainID() Hash {
	return e.r.genesisEx.ChainID
}

// NodeAddress returns the node address
func (e *Engine) NodeAddress() Address {
	return e.r.nodeAddr
}

// NodePublic returns the marshaled public key. (uncompressed form specified in section 4.3.6 of ANSI X9.62)
func (e *Engine) NodePublic() []byte {
	return PubMarshal(e.codec.c, &e.r.privateKey.PublicKey)
}

// IsRunning returns true if the engine is still running
func (e *Engine) IsRunning() bool {
	e.runningMu.RLock()
	defer e.runningMu.RUnlock()
	return e.runningCh != nil
}

func (e *Engine) IsEnrolmentPending(nodeID [32]byte) bool {
	return e.r.IsEnrolmentPending(nodeID)
}

// ConfigureNew a new instance of the rrr consensus engine. Assumes the provided
// engine instance is new.
func ConfigureNew(
	e *Engine, config *Config, codec *CipherCodec,
	privateKey *ecdsa.PrivateKey, logger Logger) {

	if config.ConfirmPhase > config.RoundLength {
		logger.Crit("confirm phase can not be longer than the round",
			"confirmphase", config.ConfirmPhase, "roundlength", config.RoundLength)
	}

	e.config = config
	e.privateKey = privateKey
	e.logger = logger

	// Only get err from NewRC if zize requested is <=0
	peerMessages, _ := lru.NewARC(lruPeers)
	e.peerMessages = peerMessages
	selfMessages, _ := lru.NewARC(lruMessages)
	e.selfMessages = selfMessages

	e.r = NewRoundState(codec, privateKey, config, logger)
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
	if err := e.r.PrimeActiveSelection(chain); err != nil {
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
	e.r.StartRounds(e, chain)

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

				e.r.NewChainHead(e, chain, et.BlockHeader)

			// new work from the miner
			case *EngSealTask:

				e.r.NewSealTask(e, et)

			// Consensus protocol: a leaders signed intent to produce a block
			case *EngSignedIntent:

				e.r.NewSignedIntent(et)

			// Consensus protocol: endorsers responding to a leaders intent
			case *EngSignedEndorsement:

				e.r.NewSignedEndorsement(et)

			// enrolment of new identities post genesis. XXX: TODO make this (at
			// least) respect --permissioned and permissioned-nodes.json. Longer
			// term we would like to consider identity mining as descibed in the
			// paper.
			case *EngEnrolIdentity:

				e.r.QueueEnrolment(et)

			default:
				e.logger.Info("rrr engine.run received unknown type", "v", i)
			}

		case <-e.r.T.Ticker.C:

			e.r.PhaseTick(e, chain)
		}
	}
}

// HandleMsg handles a message from peer
func (e *Engine) HandleMsg(peerAddr Address, msg []byte) (bool, error) {

	var err error

	msgHash := Keccak256Hash(e.codec.c, msg)

	rmsg := &RMsg{}
	if err = e.codec.DecodeBytes(msg, rmsg); err != nil {
		return true, err
	}

	e.logger.Trace(
		"RRR HandleMsg", "#msg", msgHash.Hex(),
		"#raw", e.codec.Keccak256Hash(rmsg.Raw).Hex())

	// Note: it is the msgHash we want here, not the raw hash. We want it to be
	// possible for leader candidates to request a re-evaluation of the same
	// block proposal. Otherwise they can get stuck in small network scenarios.
	if seen := e.updateInboundMsgTracking(peerAddr, msgHash); seen {
		e.logger.Trace("RRR HandleMsg - ignoring previously seen")
		return true, nil
	}

	switch rmsg.Code {
	case RMsgIntent:

		e.logger.Trace("RRR HandleMsg - post engSignedIntent")

		si := &EngSignedIntent{ReceivedAt: time.Now(), Seq: rmsg.Seq}

		if si.Pub, err = e.codec.DecodeSignedIntent(&si.SignedIntent, rmsg.Raw); err != nil {
			e.logger.Info("RRR Intent decodeverify failed", "err", err)
			return true, err
		}

		if !e.PostIfRunning(si) {
			e.logger.Info("RRR Intent engine not running")
		}

		return true, nil

	case RMsgConfirm:

		e.logger.Trace("RRR HandleMsg - post engSignedEndorsement")
		sc := &EngSignedEndorsement{ReceivedAt: time.Now(), Seq: rmsg.Seq}

		if sc.Pub, err = e.codec.DecodeSignedEndorsement(&sc.SignedEndorsement, rmsg.Raw); err != nil {

			e.logger.Debug("RRR Endorsement decodeverify failed", "err", err)
			return true, err
		}

		e.PostIfRunning(sc)
		return true, nil

	default:
		return true, ErrRMsgInvalidCode
	}
}

func (e *Engine) FindPeers(
	peers map[Address]bool) map[Address]Peer {

	return e.peerFinder.FindPeers(peers)
}

// Send the message to the peer - if its hash is not in the ARU cache for the
// peer
func (e *Engine) Send(peerAddr Address, msg []byte) error {
	e.logger.Trace("RRR Send")

	msgHash := e.codec.Keccak256Hash(msg)

	peers := e.peerFinder.FindPeers(map[Address]bool{peerAddr: true})
	if len(peers) != 1 {
		return fmt.Errorf("RRR Send - no peer connection")
	}
	peer := peers[peerAddr]
	if peer == nil {
		return fmt.Errorf("internal error, FindPeers returning unasked for peer")
	}
	return e.peerSend(peer, peerAddr, msg, msgHash)
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
	go peer.ConsensusMsg(msg)
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
			ChainID:    e.r.genesisEx.ChainID,
			EndorserID: e.r.nodeID,
		},
	}

	var err error
	c.IntentHash, err = e.codec.HashIntent(&et.SignedIntent.Intent)
	if err != nil {
		return err
	}

	// Note: by including the senders sequence, and remembering that the sender
	// will be changing the round also, we can be sure we will reply even if
	// the intent is otherwise a duplicate.
	rmsg := &RMsg{Code: RMsgConfirm, Seq: et.Seq}

	rmsg.Raw, err = e.codec.EncodeSignEndorsement(c, e.privateKey)
	if err != nil {
		e.logger.Info("RRR encoding SignedEndorsement", "err", err.Error())
		return err
	}
	msg, err := e.codec.EncodeToBytes(rmsg)
	if err != nil {
		e.logger.Info("RRR encoding RMsgConfirm", "err", err.Error())
		return err
	}

	e.logger.Debug("RRR sending confirmation",
		"candidate", et.SignedIntent.NodeID.Hex(),
		"endorser", e.r.nodeID.Hex())

	// find the peer candidate
	return e.Send(intenderAddr, msg)
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
	return e.r.CalcDifficulty(e.r.nodeAddr)
}

func (e *Engine) VerifySeal(chain VerifyBranchChainReader, header BlockHeader) error {

	if _, err := e.r.VerifyHeader(chain, header); err != nil {
		return err
	}
	return nil
}

func (e *Engine) VerifyHeader(chain headerByNumberChainReader, header BlockHeader) error {
	_, err := e.r.VerifyHeader(chain, header)
	return err
}

func (e *Engine) VerifyBranchHeaders(
	chain VerifyBranchChainReader, header BlockHeader, parents []BlockHeader) error {
	return e.r.VerifyBranchHeaders(chain, header, parents)
}

// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (e *Engine) Author(header BlockHeader) (Address, error) {

	_, sealerID, _, err := e.codec.DecodeHeaderSeal(header)
	if err != nil {
		return Address{}, err
	}

	sealingNodeAddr := sealerID.Address()

	if sealingNodeAddr == e.r.nodeAddr {
		e.logger.Debug("RRR Author - sealed by self", "addr", sealingNodeAddr, "bn", header.GetNumber())
	} else {
		e.logger.Debug("RRR Author sealed by", "addr", sealingNodeAddr, "bn", header.GetNumber())
	}
	return sealingNodeAddr, nil
}
