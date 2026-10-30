package types

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestAddressForIsDeterministic(t *testing.T) {
	creator := common.HexToAddress("0x00000000000000000000000000000000000000EE")

	first := AddressFor(creator, 0)
	second := AddressFor(creator, 0)
	if first != second {
		t.Fatalf("same input produced different addresses: %s vs %s", first, second)
	}

	if AddressFor(creator, 1) == first {
		t.Fatal("sequence 1 must not produce the same address as sequence 0")
	}

	other := common.HexToAddress("0x00000000000000000000000000000000000000AB")
	if AddressFor(other, 0) == first {
		t.Fatal("different creators must not produce the same address")
	}
}

func TestAddressForMatchesDocumentedPreimage(t *testing.T) {
	creator := common.HexToAddress("0x00000000000000000000000000000000000000EE")

	// Off-chain reproduction: sha256("karsa/native/<lowercase>/<seq>")[12:]
	sum := sha256.Sum256([]byte("karsa/native/0x00000000000000000000000000000000000000ee/0"))
	want := common.BytesToAddress(sum[12:])

	if got := AddressFor(creator, 0); got != want {
		t.Fatalf("derivation mismatch: %s != %s", got, want)
	}
}

func TestDenomRoundTrip(t *testing.T) {
	creator := common.HexToAddress("0x00000000000000000000000000000000000000EE")
	address := AddressFor(creator, 7)

	denom := DenomFor(address)
	if len(denom) != DenomLen {
		t.Fatalf("denom %q has length %d, want %d", denom, len(denom), DenomLen)
	}
	if !strings.HasPrefix(denom, "n:0x") {
		t.Fatalf("denom %q does not start with n:0x", denom)
	}
	if denom != strings.ToLower(denom) {
		t.Fatalf("denom %q must be lowercase", denom)
	}

	parsed, ok := AddressFromDenom(denom)
	if !ok {
		t.Fatalf("AddressFromDenom(%q) failed", denom)
	}
	if parsed != address {
		t.Fatalf("round trip mismatch: %s != %s", parsed, address)
	}
}

func TestAddressFromDenomRejectsInvalid(t *testing.T) {
	address := AddressFor(common.HexToAddress("0x00000000000000000000000000000000000000EE"), 0)

	cases := []string{
		"",
		"akra",
		"erc20:0x0000000000000000000000000000000000000001",
		"n/momo",
		"n:0x1234",
		DenomPrefix + strings.ToUpper(address.Hex()), // mixed case
		"n:0xzzzz0000000000000000000000000000000000",
	}

	for _, denom := range cases {
		if _, ok := AddressFromDenom(denom); ok {
			t.Errorf("AddressFromDenom(%q) should have failed", denom)
		}
		if IsNativeTokenDenom(denom) {
			t.Errorf("IsNativeTokenDenom(%q) should be false", denom)
		}
	}
}

func TestIsReservedAddress(t *testing.T) {
	reserved := []string{
		"0x0000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000100",
		"0x0000000000000000000000000000000000000800",
		"0x0000000000000000000000000000000000000900",
		"0x0000000000000000000000000000000000000902",
		"0x00000000000000000000000000000000000009ff",
	}
	for _, hexAddr := range reserved {
		if !IsReservedAddress(common.HexToAddress(hexAddr)) {
			t.Errorf("%s should be reserved", hexAddr)
		}
	}

	free := []string{
		"0x0000000000000000000000000000000000000000",
		"0x0000000000000000000000000000000000000a00",
		"0x0000000000000000000000000000000000001234",
		"0x1000000000000000000000000000000000000001",
	}
	for _, hexAddr := range free {
		if IsReservedAddress(common.HexToAddress(hexAddr)) {
			t.Errorf("%s should not be reserved", hexAddr)
		}
	}
}
