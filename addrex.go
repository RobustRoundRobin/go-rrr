package rrr

import "fmt"

// abreviated addresses, so we can more densly report node identities in logs

// HexShort returns an abbreviated hex address
func (a Address) HexShort() string {
	return fmtAddrex(a, 3, 2)
}

// return the hex string formed from the first head 'h' bytes, and last tail 't' bytes as hex,
// formatted with a single '.'. h and t are clamped to len(Address) / 2 - 1
func fmtAddrex(addr Address, h, t int) string {

	x := addr.Hex()

	if h < 1 && t < 1 {
		return ""
	}

	if h < 0 {
		h = 0
	}

	if h > len(x) {
		h = len(x)
	}

	if t < 0 {
		t = 0
	}

	// give precedence to the head length
	if len(x)-h < t {
		t = len(x) - h
	}

	start := x[:h]
	end := x[len(x)-t:]

	return fmt.Sprintf("%s.%s", start, end)
}
