package pcap

import (
	"encoding/binary"
	"io"
	"net"
)

// Writer writes packets into standard libpcap format.
type Writer struct {
	w io.Writer
}

// NewWriter initializes a new PCAP stream writer with standard libpcap global header.
func NewWriter(w io.Writer) (*Writer, error) {
	pw := &Writer{w: w}
	// PCAP Global Header (24 bytes)
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4) // Magic Number
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // Major Version
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // Minor Version
	binary.LittleEndian.PutUint32(hdr[8:12], 0)         // ThisZone (GMT)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)        // SigFigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)    // SnapLen
	binary.LittleEndian.PutUint32(hdr[20:24], 1)        // LinkType: LINKTYPE_ETHERNET (1)

	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return pw, nil
}

// WriteTCPPacket writes a single TCP packet encapsulating the given payload on dstPort.
func (pw *Writer) WriteTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) error {
	ethHdr := make([]byte, 14)
	copy(ethHdr[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // Dst MAC
	copy(ethHdr[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}) // Src MAC
	binary.BigEndian.PutUint16(ethHdr[12:14], 0x0800)               // EtherType: IPv4

	// IPv4 Header (20 bytes)
	ipLen := 20 + 20 + len(payload)
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	ipHdr[1] = 0x00 // DSCP / ECN
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(ipHdr[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(ipHdr[6:8], 0x4000) // DF flag
	ipHdr[8] = 64                                  // TTL
	ipHdr[9] = 6                                   // Protocol: TCP
	copy(ipHdr[12:16], srcIP.To4())
	copy(ipHdr[16:20], dstIP.To4())
	ipChecksum := checksum(ipHdr)
	binary.BigEndian.PutUint16(ipHdr[10:12], ipChecksum)

	// TCP Header (20 bytes)
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], 1)        // Seq
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)       // Ack
	tcpHdr[12] = 0x50                                // Data offset (5 words = 20 bytes)
	tcpHdr[13] = 0x18                                // Flags: PSH, ACK
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535) // Window size

	// TCP Checksum (pseudo-header + TCP header + payload)
	pseudoHdr := make([]byte, 12)
	copy(pseudoHdr[0:4], srcIP.To4())
	copy(pseudoHdr[4:8], dstIP.To4())
	pseudoHdr[8] = 0
	pseudoHdr[9] = 6
	binary.BigEndian.PutUint16(pseudoHdr[10:12], uint16(20+len(payload)))

	tcpChecksum := tcpChecksumCalc(pseudoHdr, tcpHdr, payload)
	binary.BigEndian.PutUint16(tcpHdr[16:18], tcpChecksum)

	totalLen := len(ethHdr) + len(ipHdr) + len(tcpHdr) + len(payload)

	// Packet Header (16 bytes)
	pktHdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(pktHdr[0:4], 1700000000)    // Seconds
	binary.LittleEndian.PutUint32(pktHdr[4:8], 0)             // Microseconds
	binary.LittleEndian.PutUint32(pktHdr[8:12], uint32(totalLen)) // Captured length
	binary.LittleEndian.PutUint32(pktHdr[12:16], uint32(totalLen)) // Original length

	if _, err := pw.w.Write(pktHdr); err != nil {
		return err
	}
	if _, err := pw.w.Write(ethHdr); err != nil {
		return err
	}
	if _, err := pw.w.Write(ipHdr); err != nil {
		return err
	}
	if _, err := pw.w.Write(tcpHdr); err != nil {
		return err
	}
	if _, err := pw.w.Write(payload); err != nil {
		return err
	}
	return nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksumCalc(pseudo, tcp, payload []byte) uint16 {
	var sum uint32
	for i := 0; i < len(pseudo)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i < len(tcp)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
