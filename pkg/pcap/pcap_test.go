package pcap_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"ans2go/pkg/pcap"
)

func TestPcapWriter(t *testing.T) {
	var buf bytes.Buffer
	pw, err := pcap.NewWriter(&buf)
	if err != nil {
		t.Fatalf("NewWriter error: %v", err)
	}

	// Verify global header
	if buf.Len() != 24 {
		t.Fatalf("expected 24 bytes global header, got %d", buf.Len())
	}
	magic := binary.LittleEndian.Uint32(buf.Bytes()[0:4])
	if magic != 0xA1B2C3D4 {
		t.Fatalf("expected magic 0xA1B2C3D4, got 0x%08X", magic)
	}

	// Write packet
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	if err := pw.WriteTCPPacket(srcIP, dstIP, 12345, 7275, payload); err != nil {
		t.Fatalf("WriteTCPPacket error: %v", err)
	}

	expectedPacketLen := 16 + 14 + 20 + 20 + 4
	if buf.Len() != 24+expectedPacketLen {
		t.Fatalf("expected total length %d, got %d", 24+expectedPacketLen, buf.Len())
	}
}
