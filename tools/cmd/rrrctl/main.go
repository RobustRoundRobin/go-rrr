package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/RobustRoundRobin/go-rrr/consensus/rrr"
	"github.com/RobustRoundRobin/go-rrr/secp256k1suite"
	"github.com/ethereum/go-ethereum/common"
	qrrr "github.com/ethereum/go-ethereum/consensus/rrr"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"gopkg.in/urfave/cli.v1"
)

var (
	// Git information set by linker when building with ci.go.
	gitCommit string
	gitDate   string
	app       = &cli.App{
		Name:        filepath.Base(os.Args[0]),
		Usage:       "RobustRoundRobin consensus tool for ConsenSys/quorum",
		Version:     params.VersionWithCommit(gitCommit, gitDate),
		Writer:      os.Stdout,
		HideVersion: true,
	}
)

func init() {
	// Set up the CLI app.

	app.CommandNotFound = func(ctx *cli.Context, cmd string) {
		fmt.Fprintf(os.Stderr, "No such command: %s\n", cmd)
		os.Exit(1)
	}

	// Add subcommands.
	app.Commands = []cli.Command{
		genesisExtraCommand,
		inspectHeader,
	}
}

var genesisExtraCommand = cli.Command{
	Name:   "genextra",
	Usage:  "Extra data for genesis document",
	Action: genextra,
	Flags: []cli.Flag{
		cli.BoolFlag{Name: "showids", Usage: "Also print the corresponding identities (node addresses)"},
		cli.StringFlag{Name: "datadir", Usage: "by default look for static-nodes.json in this directory"},
		cli.StringFlag{Name: "keyhex", Usage: "private key as hex string"},
		cli.StringFlag{Name: "keyfile", Value: "key", Usage: "key file name, relative to datadir"},
		cli.StringFlag{Name: "alphadir", Usage: "The file names for VRF alpha contribution are interpreted relative to this directory (and datadir if it is not provided)"},
	},
}

var inspectHeader = cli.Command{
	Name:   "inspectheaders",
	Usage:  "Get a block from a live node and inspect the rrr details in the header",
	Action: inspectheaders,
	Flags: []cli.Flag{
		cli.StringFlag{Name: "endpoint", Usage: "http(s)://host:port to connect to"},
		cli.Int64Flag{Name: "start", Usage: "first to GET"},
		cli.Int64Flag{Name: "end", Usage: "last to GET"},
	},
}

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

func inspectheaders(ctx *cli.Context) error {
	codec := NewCodec()

	endpoint := ctx.String("endpoint")
	eth, err := newEthClient(endpoint)
	if err != nil {
		return fmt.Errorf("creating eth client: %w", err)
	}

	start := ctx.Int64("start")
	end := ctx.Int64("end")
	if end < start {
		return fmt.Errorf("start cant be greater than end")
	}

	tprev := int64(-1)
	if start >= 1 {

		block, err := eth.BlockByNumber(context.TODO(), new(big.Int).SetInt64(start-1))
		if err != nil {
			return fmt.Errorf("eth_blockByNumber %d: %w", start-1, err)
		}
		tprev = int64(block.Header().Time)
	}
	for n := start; n <= end; n++ {

		block, err := eth.BlockByNumber(context.TODO(), new(big.Int).SetInt64(n))
		if err != nil {
			return fmt.Errorf("eth_blockByNumberd: %w", err)
		}
		h := block.Header()
		header := qrrr.NewBlockHeader(h)
		a := &rrr.BlockActivity{}
		if err := codec.DecodeBlockActivity(a, rrr.Hash{}, header); err != nil {
			return fmt.Errorf("decoding block activity: %w", err)
		}
		// print out block number, sealer, endorer1 ... endorsern
		delta := "NaN"
		if tprev != -1 {
			delta = fmt.Sprintf("%d", int64(h.Time)-tprev)
		}
		tprev = int64(h.Time)

		s := int64(h.Time)
		t := time.Unix(s, 0).Format(time.RFC3339)
		fmt.Printf("%d %s %s %s", header.GetNumber().Int64(), a.SealerID.Hex(), delta, t)
		for _, e := range a.Confirm {
			fmt.Printf(" %s", e.EndorserID.Hex())
		}
		fmt.Println("")

	}

	return nil
}

func newEthClient(ethEndpoint string) (*ethclient.Client, error) {

	ethRPC, err := rpc.DialHTTPWithClient(ethEndpoint, &http.Client{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}
	ethClient := ethclient.NewClient(ethRPC)
	if ethClient == nil {
		return nil, fmt.Errorf("failed creating ethclient")
	}

	return ethClient, nil
}

func genextra(ctx *cli.Context) error {

	var err error

	cipherSuite := secp256k1suite.NewCipherSuite()
	cipherCodec := NewCodec()

	dataDir := ctx.String("datadir")
	alphaDir := ctx.String("alphadir")
	if len(alphaDir) == 0 {
		alphaDir = dataDir
	}

	if ctx.NArg() == 0 {
		return fmt.Errorf("provide one or more alpha contribution files in the order you would like the identities enroled")
	}

	var key *ecdsa.PrivateKey

	keyhex := ctx.String("keyhex")
	if keyhex != "" {
		if key, err = crypto.HexToECDSA(keyhex); err != nil {
			return err
		}

	} else {

		key, err = crypto.LoadECDSA(resolvePath(dataDir, ctx.String("keyfile")))
		if err != nil {
			return err
		}
	}

	signerNodeID := rrr.NodeIDFromPub(cipherSuite, &key.PublicKey)

	args := ctx.Args()

	var initIdents []rrr.Enrolment

	alpha := make(map[rrr.Hash]rrr.Alpha)
	order := make([]common.Hash, len(args))

	for i := 0; i < len(args); i++ {

		filepath := resolvePath(alphaDir, args[i])
		nodeID, contrib, err := readAlphaContrib(filepath)
		if err != nil {
			return fmt.Errorf("file `%s':%w", filepath, err)
		}
		order[i] = nodeID
		if initIdents, err = rrr.IdentInit(cipherCodec, key, initIdents, rrr.Hash(nodeID)); err != nil {
			return fmt.Errorf("file `%s':%w", filepath, err)
		}
		alpha[rrr.Hash(nodeID)] = contrib
	}

	extra := &rrr.GenesisExtraData{}

	if err := cipherCodec.PopulateChainInit(&extra.ChainInit, key, initIdents, alpha); err != nil {
		return err
	}

	data, err := cipherCodec.EncodeHashGenesisExtraData(extra)
	if err != nil {
		return err
	}
	extraData := hex.EncodeToString(data)

	// Before printing out the data, make sure it round trips ok.
	extraDecoded := &rrr.GenesisExtraData{}
	err = cipherCodec.DecodeGenesisExtra(data, extraDecoded)
	if err != nil {
		return err
	}

	decodedSignerNodeID, err := cipherCodec.RecoverEnrolerID(extraDecoded.IdentInit[0].Q, extraDecoded.IdentInit[0].U)
	if err != nil {
		return err
	}
	if decodedSignerNodeID != signerNodeID {
		return fmt.Errorf("genesis extra data serialisation is broken")
	}
	fmt.Println(extraData)

	if ctx.Bool("showids") {
		for i, nodeID := range order {
			fmt.Printf("%02d %s\n", i, rrr.Hash(nodeID).Address().Hex())
		}
	}

	return nil
}

type alphaDoc struct {
	NodeID string `json:"nodeid"`
	Alpha  string `json:"alpha"`
	Sig    string `json:"sig"`
}

func readAlphaContrib(filepath string) (common.Hash, rrr.Alpha, error) {
	// Load the nodes from the config file.

	doc := &alphaDoc{}

	if err := common.LoadJSON(filepath, doc); err != nil {
		return common.Hash{}, rrr.Alpha{}, fmt.Errorf("loading file `%s': %v", filepath, err)
	}

	if doc.NodeID == "" {
		return common.Hash{}, rrr.Alpha{}, fmt.Errorf("file `%s' missing nodeid", filepath)
	}
	nodeID := common.HexToHash(doc.NodeID)

	a := rrr.Alpha{}
	if doc.Alpha == "" {
		return common.Hash{}, rrr.Alpha{}, fmt.Errorf("file `%s' missing alpha", filepath)
	}
	a.Contribution = rrr.Hash(common.HexToHash(doc.Alpha))
	if doc.Sig == "" {
		return common.Hash{}, rrr.Alpha{}, fmt.Errorf("file `%s' missing sig over alpha", filepath)
	}
	b := common.FromHex(doc.Sig)
	if len(b) != 65 {
		return common.Hash{}, rrr.Alpha{}, fmt.Errorf("bad sig len %d `%s'", len(b), doc.Sig)
	}
	n := copy(a.Sig[:], b)
	if n != 65 {
		return common.Hash{}, rrr.Alpha{}, fmt.Errorf("copy sigbytes failed %d", n)
	}
	return nodeID, a, nil
}

func resolvePath(dataDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if dataDir != "" {
		return filepath.Join(dataDir, path)
	}
	return path
}

func main() {
	exit(app.Run(os.Args))
}

func exit(err interface{}) {
	if err == nil {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
