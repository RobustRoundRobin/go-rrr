module github.com/RobustRoundRobin/go-rrr/secp256k1suite

go 1.15

// TZ=UTC git --no-pager show --quiet --abbrev=12 --date='format-local:%Y%m%d%H%M%S' --format="%cd-%h"
replace github.com/ethereum/go-ethereum/crypto/secp256k1 => github.com/RobustRoundRobin/quorum/crypto/secp256k1 v0.0.0-20210502124651-0808972d766e

require (
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/ethereum/go-ethereum v1.10.3
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf
)
