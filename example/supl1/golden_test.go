package supl1_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"ans2go/example/supl1"
)

func ptr[T any](v T) *T {
	return &v
}

// TestGolden_SUPLEND_ProtocolError tests an ITU-T X.691 bit-by-bit verified golden vector for SUPL END.
//
// Normative specification breakdown (exactly 56 bits = 7 octets):
// - Length: 12 (0x000C) in 16 bits -> 00000000 00001100 (0x00, 0x0C)
// - Version: Maj=2, Min=0, Servind=0 in 3x8 bits -> 00000010 00000000 00000000 (0x02, 0x00, 0x00)
// - SessionID (non-extensible):
//   * setSessionID present: 0
//   * slpSessionID present: 0
//   -> 2 bits: 00b
// - UlpMessage (extensible choice, 8 root alternatives):
//   * Ext bit: 0
//   * msSUPLEND index 5 in 3 bits (ceil(log2(8))): 101b
//   -> 4 bits: 0101b
// - SUPLEND (extensible sequence, 3 root optional components):
//   * Ext bit: 0
//   * Preamble: position=0, statusCode=1, ver=0
//   -> 4 bits: 0010b
// - StatusCode (extensible enum, 20 root items):
//   * Ext bit: 0
//   * protocolError index 3 in 5 bits (ceil(log2(20))): 00011b
//   -> 6 bits: 000011b
//
// Bit stream assembly:
// Octet 0..4: 00 0C 02 00 00
// Octet 5: [0 0] (sessionID) + [0 1 0 1] (choice) + [0] (SUPLEND ext) + [0] (pos opt) = 00010100b = 0x14
// Octet 6: [1] (status opt) + [0] (ver opt) + [0] (status ext) + [0 0 0 1 1] (status val) = 10000011b = 0x83
//
// Exactly 7 octets: 00 0C 02 00 00 14 83
func TestGolden_SUPLEND_ProtocolError(t *testing.T) {
	expectedHex := "000c0200001483"
	expectedBytes, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("hex decode error: %v", err)
	}

	// 1. Construct Go struct
	pdu := supl1.ULPPDU{
		Length: 12,
		Version: supl1.Version{
			Maj:     2,
			Min:     0,
			Servind: 0,
		},
		SessionID: supl1.SessionID{},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLEND,
			MsSUPLEND: &supl1.SUPLEND{
				StatusCode: ptr(supl1.StatusCode_ProtocolError),
			},
		},
	}

	// 2. Encode to UPER
	encoded, err := supl1.Marshal(&pdu)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if !bytes.Equal(encoded, expectedBytes) {
		t.Fatalf("Golden vector mismatch:\n  got:  %X\n  want: %X", encoded, expectedBytes)
	}

	// 3. Decode from golden hex
	var decoded supl1.ULPPDU
	if err := supl1.Unmarshal(expectedBytes, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// 4. Verify decoded fields
	if decoded.Length != 12 {
		t.Fatalf("expected Length=12, got %d", decoded.Length)
	}
	if decoded.Version.Maj != 2 || decoded.Version.Min != 0 || decoded.Version.Servind != 0 {
		t.Fatalf("unexpected version: %+v", decoded.Version)
	}
	if decoded.Message.Choice != supl1.UlpMessageChoice_MsSUPLEND {
		t.Fatalf("unexpected message choice: %v", decoded.Message.Choice)
	}
	if decoded.Message.MsSUPLEND == nil || decoded.Message.MsSUPLEND.StatusCode == nil {
		t.Fatalf("missing SUPLEND or StatusCode in decoded")
	}
	if *decoded.Message.MsSUPLEND.StatusCode != supl1.StatusCode_ProtocolError {
		t.Fatalf("expected StatusCode_ProtocolError, got %v", *decoded.Message.MsSUPLEND.StatusCode)
	}
}

// TestGolden_SUPLEND_Unspecified tests golden vector for StatusCode_Unspecified (value 0).
// Exactly 7 octets: 00 08 02 00 00 14 80
func TestGolden_SUPLEND_Unspecified(t *testing.T) {
	expectedHex := "00080200001480"
	expectedBytes, _ := hex.DecodeString(expectedHex)

	pdu := supl1.ULPPDU{
		Length: 8,
		Version: supl1.Version{
			Maj:     2,
			Min:     0,
			Servind: 0,
		},
		SessionID: supl1.SessionID{},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLEND,
			MsSUPLEND: &supl1.SUPLEND{
				StatusCode: ptr(supl1.StatusCode_Unspecified),
			},
		},
	}

	encoded, err := supl1.Marshal(&pdu)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if !bytes.Equal(encoded, expectedBytes) {
		t.Fatalf("Golden vector mismatch:\n  got:  %X\n  want: %X", encoded, expectedBytes)
	}

	var decoded supl1.ULPPDU
	if err := supl1.Unmarshal(expectedBytes, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if *decoded.Message.MsSUPLEND.StatusCode != supl1.StatusCode_Unspecified {
		t.Fatalf("expected StatusCode_Unspecified, got %v", *decoded.Message.MsSUPLEND.StatusCode)
	}
}
