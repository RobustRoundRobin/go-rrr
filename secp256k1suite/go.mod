module github.com/RobustRoundRobin/go-rrr/secp256k1suite

go 1.15

// TZ=UTC git --no-pager show --quiet --abbrev=12 --date='format-local:%Y%m%d%H%M%S' --format="%cd-%h"

require (
	github.com/btcsuite/btcd v0.21.0-beta
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf
)
