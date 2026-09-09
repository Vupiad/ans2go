package ilp_test

import (
	"bytes"
	"testing"

	"ans2go/example/ilp"
)

func TestILPIPAddressRoundtrip(t *testing.T) {
	ipv4 := []byte{192, 168, 1, 1}
	ip := ilp.IPAddress{
		Choice:      ilp.IPAddressChoice_Ipv4Address,
		Ipv4Address: &ipv4,
	}

	encoded, err := ilp.Marshal(&ip)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ilp.IPAddress
	if err := ilp.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Choice != ilp.IPAddressChoice_Ipv4Address {
		t.Fatalf("expected choice IPv4, got %v", decoded.Choice)
	}
	if decoded.Ipv4Address == nil || !bytes.Equal(*decoded.Ipv4Address, ipv4) {
		t.Fatalf("expected %v, got %v", ipv4, decoded.Ipv4Address)
	}
}

func TestILPSessionID2Roundtrip(t *testing.T) {
	ipv4 := []byte{10, 0, 0, 1}
	sess := ilp.SessionID2{
		SlcSessionID: ilp.SlcSessionID{
			SessionID: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			SlcId: ilp.NodeAddress{
				Choice: ilp.NodeAddressChoice_IPAddress,
				IPAddress: &ilp.IPAddress{
					Choice:      ilp.IPAddressChoice_Ipv4Address,
					Ipv4Address: &ipv4,
				},
			},
		},
	}

	encoded, err := ilp.Marshal(&sess)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ilp.SessionID2
	if err := ilp.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !bytes.Equal(decoded.SlcSessionID.SessionID, sess.SlcSessionID.SessionID) {
		t.Fatalf("SessionID mismatch: got %v, want %v", decoded.SlcSessionID.SessionID, sess.SlcSessionID.SessionID)
	}
	if decoded.SlcSessionID.SlcId.Choice != ilp.NodeAddressChoice_IPAddress {
		t.Fatalf("expected IPAddress choice, got %v", decoded.SlcSessionID.SlcId.Choice)
	}
}
