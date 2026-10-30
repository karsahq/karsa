package types

import "testing"

func TestCustodyAddressIsDeterministic(t *testing.T) {
	first := CustodyAddress(1)
	if first != CustodyAddress(1) {
		t.Fatal("same pool id must derive the same custody address")
	}
	if first == CustodyAddress(2) {
		t.Fatal("different pool ids must derive different custody addresses")
	}
}

func TestCustodyAddressIsDisjointFromLP(t *testing.T) {
	for id := uint64(1); id <= 16; id++ {
		if CustodyAddress(id) == LPAssetAddress(LPDenom(id)) {
			t.Fatalf("pool %d: custody address collides with the LP asset address", id)
		}
	}
}
