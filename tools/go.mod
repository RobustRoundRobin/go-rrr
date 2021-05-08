module github.com/RobustRoundRobin/go-rrr/tools

go 1.15

replace (
	github.com/RobustRoundRobin/go-rrr/consensus => ../consensus
	github.com/RobustRoundRobin/go-rrr/secp256k1suite => ../secp256k1suite
)

require (
	github.com/RobustRoundRobin/go-rrr/consensus v0.0.0-00010101000000-000000000000
	github.com/RobustRoundRobin/go-rrr/secp256k1suite v0.0.0-00010101000000-000000000000
	github.com/ethereum/go-ethereum v1.10.3
	github.com/stretchr/testify v1.7.0
	github.com/vechain/go-ecvrf v0.0.0-20200326080414-5b7e9ee61906
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf
)
