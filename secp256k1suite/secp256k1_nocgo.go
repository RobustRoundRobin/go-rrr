package secp256k1suite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/sha3"
)

// Notice: this work benefits greatly from go-ethereum/crypto/signature_cgo.go
// but has been re-written from primary sources to avoid licensing issues.

var (
	// groupOrderN "An ECDSA signature consists of two integers, called R and S. The
	// secp256k1 group order, called N, is a constant value for all secp256k1
	// signatures. Specifically, N is the value" -- https://xrpl.org/transaction-malleability.html
	groupOrderN = []byte(
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41")
	halfN = []byte(
		"\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x5d\x57\x6e\x73\x57\xa4\x50\x1d\xdf\xe9\x2f\x46\x68\x1b\x20\xa0")

	halfNbig = new(big.Int).SetBytes(halfN)
)

// NewCipherSuite returns the CipherSuite selected by the package build tags (csecp present or not)
func NewCipherSuite() CipherSuite {
	return &SECP256k1SuiteBTCEC{}
}

func N() []byte {
	n := make([]byte, len(groupOrderN))
	copy(n, groupOrderN)
	return n
}

// SmallS checks that s is the 'canonical' of the two values satisfying the
// curve. See // https://yondon.blog/2019/01/01/how-not-to-use-ecdsa/ In short,
// for an ecdsa signature  [R, S] there are, due to curve symetry, two possible
// values of S that would otherwise pass EC verification. The world has chosen
// the smaller of the two possible values as 'canonical'. The half value is
// defined as canonical.
func SmallS(s *big.Int) bool {

	// If s is <= half the group order then it is NOT the larger. Note that s ==
	// halfN is canonical
	return s.Cmp(halfNbig) <= 0
}

// Moves the ec pub key recovery id from the front to the back of the slice.
//
// Archaeology: ...
// SEC 1-v2 [1] describes how signature recovery works and the ASN.1 encoding of
// the extra information for recovery can be included. This format is
// essentially [R, S, V] (though a mnemonic for 'additional' is used rather than
// V). This heritiage means the Sign primitive puts V at the end. But in much of
// the litterature v is refered to as the 'header' and is typically listed
// first.  Ethereum (unlike bitcoin) uses the recovery trick to eliminate the
// need to include public keys with signatures. The EYP Appendix F [2], and many
// others, treat v as a header value and encode it first as it is needed to
// interpret the subsequent data. Ecrecover is due to ethereum and Sign is due
// to the ECDSA standards, hence Sign produces one format while recovery expects
// the other. The magical 27 is due to ethereum needing to avoid collisions with
// rlp encoding.
//
// The final confusion comes from the fact that libsecp256k1 is written to
// mostly deal only with r, s so it naturaly deals with signatures where [r:s]
// are [0:31][32:63]. But btec expects and requires v,r,s. libsecp256k1 works
// without fuss, but for btec we need this helper.
//
// 1. http://www.secg.org/sec1-v2.pdf
// 2. https://ethereum.github.io/yellowpaper/paper.pdf
//
//  This funciton will panic if len(sig) < 65.
func ToBTECSig(rsv []byte) []byte {
	vrs := make([]byte, 65)
	vrs[0] = rsv[64] + 27
	copy(vrs[1:], rsv)
	return vrs
}

// FromBTECSig is vrs -> rsv (See ToBTCSig for background). This function
// modifies the argument slice in place.
func FromBTECSig(vrs []byte) {
	v := vrs[0] - 27
	copy(vrs, vrs[1:])
	vrs[64] = v // vrs is now rsv
}

type SECP256k1SuiteBTCEC struct{}

func (c *SECP256k1SuiteBTCEC) Curve() elliptic.Curve {
	return btcec.S256()
}

// Keccak256 returns a digest suitable for Sign. (draft sha3 before the padding was added)
func (c *SECP256k1SuiteBTCEC) Keccak256(image ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, b := range image {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}

// Sign is given a digest to sign.
func (c *SECP256k1SuiteBTCEC) Sign(digest []byte, key *ecdsa.PrivateKey) ([]byte, error) {

	if len(digest) != 32 {
		return nil, fmt.Errorf("bad digest len %d, require 32", len(digest))
	}

	sig, err := btcec.SignCompact(
		btcec.S256(), (*btcec.PrivateKey)(key), digest, false)
	if err != nil {
		return nil, err
	}

	FromBTECSig(sig)

	return sig, nil
}

// VerifySignature verifies a 64 byte signature [R, S] format
func (c *SECP256k1SuiteBTCEC) VerifySignature(pub, digest, sig []byte) bool {
	if len(digest) != 32 {
		return false
	}
	if len(sig) != 64 {
		// fmt.Errorf("bad sig len %d, require 64", len(digest))
		return false
	}

	// btcec does not check for malleiable signatures
	s := new(big.Int).SetBytes(sig[32:])
	if !SmallS(s) {
		return false
	}

	// make a btec format sig
	btsig := &btcec.Signature{
		R: new(big.Int).SetBytes(sig[:32]), S: s}

	btpub, err := btcec.ParsePubKey(pub, btcec.S256())
	if err != nil {
		return false
	}

	return btsig.Verify(digest, btpub)
}

// Ecrecover a public key from a recoverable signature.
func (c *SECP256k1SuiteBTCEC) Ecrecover(digest, sig []byte) ([]byte, error) {

	vrs := ToBTECSig(sig)

	btpub, _, err := btcec.RecoverCompact(btcec.S256(), vrs, digest)
	pub := (*ecdsa.PublicKey)(btpub)
	if err != nil {
		return nil, err
	}

	b := (*btcec.PublicKey)(pub).SerializeUncompressed()
	return b, err
}
