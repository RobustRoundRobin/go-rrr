module github.com/RobustRoundRobin/go-rrr/tools

go 1.15

replace (
	github.com/RobustRoundRobin/go-rrr/consensus => ../consensus
	github.com/RobustRoundRobin/go-rrr/secp256k1suite => ../secp256k1suite
	github.com/ethereum/go-ethereum => ../../quorum
	github.com/ethereum/go-ethereum/crypto/secp256k1 => github.com/ConsenSys/goquorum-crypto-secp256k1 v0.0.2
)

require (
	github.com/RobustRoundRobin/go-rrr/consensus v0.1.5
	github.com/RobustRoundRobin/go-rrr/secp256k1suite v0.0.0-00010101000000-000000000000
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/ethereum/go-ethereum v1.10.8
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-sqlite3 v1.11.0
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/vechain/go-ecvrf v0.0.0-20200326080414-5b7e9ee61906
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	gopkg.in/urfave/cli.v1 v1.20.0
)
