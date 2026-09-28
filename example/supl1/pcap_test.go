package supl1_test

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ans2go/example/supl1"
	"ans2go/pkg/pcap"
)

// TestGenerateSUPLPcapAndValidateWireshark generates a standard PCAP file containing
// SUPL packets on TCP port 7275 and executes tshark (if available) to verify that
// Wireshark's built-in UPER dissector decodes them without any Malformed Packet errors.
func TestGenerateSUPLPcapAndValidateWireshark(t *testing.T) {
	pcapPath := filepath.Join(t.TempDir(), "supl_test.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("failed to create pcap file: %v", err)
	}
	defer f.Close()

	pw, err := pcap.NewWriter(f)
	if err != nil {
		t.Fatalf("failed to create pcap writer: %v", err)
	}

	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.0.1")

	// Packet 1: SUPL END with StatusCode
	pduEnd := supl1.ULPPDU{
		Length:  12,
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLEND,
			MsSUPLEND: &supl1.SUPLEND{
				StatusCode: ptr(supl1.StatusCode_ProtocolError),
			},
		},
	}
	encodedEnd, err := supl1.Marshal(&pduEnd)
	if err != nil {
		t.Fatalf("failed to marshal SUPLEND: %v", err)
	}
	if err := pw.WriteTCPPacket(srcIP, dstIP, 50000, 7275, encodedEnd); err != nil {
		t.Fatalf("failed to write SUPLEND packet: %v", err)
	}

	// Packet 2: SUPL START with SETCapabilities and GSM Cell
	pduStart := supl1.ULPPDU{
		Length:  25,
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SetSessionID: &supl1.SetSessionID{
				SessionId: 1234,
				SetId: supl1.SETId{
					Choice: supl1.SETIdChoice_Msisdn,
					Msisdn: ptr([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}),
				},
			},
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLSTART,
			MsSUPLSTART: &supl1.SUPLSTART{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{
						AgpsSETassisted: true,
						AgpsSETBased:    true,
						AutonomousGPS:   false,
						AFLT:            false,
						ECID:            false,
						EOTD:            false,
						OTDOA:           false,
					},
					PrefMethod: supl1.PrefMethod_AgpsSETassistedPreferred,
					PosProtocol: supl1.PosProtocol{
						Tia801: false,
						Rrlp:   true,
						Rrc:    false,
					},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice: supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{
							RefMCC: 208,
							RefMNC: 1,
							RefLAC: 1000,
							RefCI:  5000,
						},
					},
				},
			},
		},
	}
	encodedStart, err := supl1.Marshal(&pduStart)
	if err != nil {
		t.Fatalf("failed to marshal SUPLSTART: %v", err)
	}
	if err := pw.WriteTCPPacket(srcIP, dstIP, 50001, 7275, encodedStart); err != nil {
		t.Fatalf("failed to write SUPLSTART packet: %v", err)
	}

	// Packet 3: SUPL INIT with FQDN SLPAddress and Notification
	pduInit := supl1.ULPPDU{
		Length:  35,
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SlpSessionID: &supl1.SlpSessionID{
				SessionID: []byte{0xCA, 0xFE, 0xBA, 0xBE},
				SlpId: supl1.SLPAddress{
					Choice: supl1.SLPAddressChoice_FQDN,
					FQDN:   ptr(supl1.FQDN("supl.google.com")),
				},
			},
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLINIT,
			MsSUPLINIT: &supl1.SUPLINIT{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
				SLPMode:   supl1.SLPMode_Proxy,
				Notification: &supl1.Notification{
					NotificationType: supl1.NotificationType_NotificationOnly,
					EncodingType:     ptr(supl1.EncodingType_Utf8),
					RequestorId:      ptr([]byte("EmergencyServices")),
				},
			},
		},
	}
	encodedInit, err := supl1.Marshal(&pduInit)
	if err != nil {
		t.Fatalf("failed to marshal SUPLINIT: %v", err)
	}
	if err := pw.WriteTCPPacket(srcIP, dstIP, 50002, 7275, encodedInit); err != nil {
		t.Fatalf("failed to write SUPLINIT packet: %v", err)
	}

	_ = f.Close()

	// Copy to a permanent test artifact location so user can inspect it
	destPath := "supl_test.pcap"
	data, _ := os.ReadFile(pcapPath)
	if err := os.WriteFile(destPath, data, 0644); err != nil {
		t.Logf("Notice: could not write %s: %v", destPath, err)
	} else {
		t.Logf("Generated Wireshark capture file: %s (%d bytes)", destPath, len(data))
	}

	// Check if tshark is installed on the host
	tsharkPath, err := exec.LookPath("tshark")
	if err != nil {
		t.Logf("tshark not found on PATH. Generated %s is ready for manual inspection in Wireshark GUI.", destPath)
		return
	}

	// Run tshark dissection
	cmd := exec.Command(tsharkPath, "-r", pcapPath, "-V")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		t.Fatalf("tshark execution failed: %v\nOutput:\n%s", err, out.String())
	}

	outStr := out.String()
	if strings.Contains(outStr, "Malformed Packet") {
		t.Fatalf("tshark detected Malformed Packet in UPER dissection:\n%s", outStr)
	}
	if strings.Contains(outStr, "Expert Info (Error") {
		t.Fatalf("tshark detected dissector error:\n%s", outStr)
	}

	t.Logf("tshark successfully dissected all packets with 0 malformed packet errors!")
}

// TestPCAP_NetworkInitiatedFlow synthesizes a full Network-Initiated Immediate Service PCAP
// and validates it against Wireshark's packet-ulp dissector.
func TestPCAP_NetworkInitiatedFlow(t *testing.T) {
	pcapPath := filepath.Join(t.TempDir(), "supl_ni_flow.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("failed to create pcap: %v", err)
	}
	defer f.Close()

	pw, err := pcap.NewWriter(f)
	if err != nil {
		t.Fatalf("failed to create pcap writer: %v", err)
	}

	slpIP := net.ParseIP("10.0.0.1")
	setIP := net.ParseIP("192.168.1.100")

	// Message 1: SLP -> SET (SUPL INIT)
	pdu1 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SlpSessionID: &supl1.SlpSessionID{
				SessionID: []byte{0xDE, 0xAD, 0xBE, 0xEF},
				SlpId: supl1.SLPAddress{
					Choice: supl1.SLPAddressChoice_FQDN,
					FQDN:   ptr(supl1.FQDN("h-slp.carrier.net")),
				},
			},
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLINIT,
			MsSUPLINIT: &supl1.SUPLINIT{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
				SLPMode:   supl1.SLPMode_Proxy,
			},
		},
	}
	raw1, _ := supl1.Marshal(&pdu1)
	_ = pw.WriteTCPPacket(slpIP, setIP, 7275, 50001, raw1)

	// Message 2: SET -> SLP (SUPL POS INIT)
	pdu2 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SetSessionID: &supl1.SetSessionID{
				SessionId: 1001,
				SetId:     supl1.SETId{Choice: supl1.SETIdChoice_Msisdn, Msisdn: ptr([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
			},
			SlpSessionID: pdu1.SessionID.SlpSessionID,
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOSINIT,
			MsSUPLPOSINIT: &supl1.SUPLPOSINIT{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{AgpsSETassisted: true},
					PrefMethod:    supl1.PrefMethod_AgpsSETassistedPreferred,
					PosProtocol:   supl1.PosProtocol{Rrlp: true},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice:  supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{RefMCC: 310, RefMNC: 260, RefLAC: 100, RefCI: 200},
					},
				},
			},
		},
	}
	raw2, _ := supl1.Marshal(&pdu2)
	_ = pw.WriteTCPPacket(setIP, slpIP, 50001, 7275, raw2)

	// Message 3: SLP -> SET (SUPL POS - RRLP assistance data)
	pdu3 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: pdu2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOS,
			MsSUPLPOS: &supl1.SUPLPOS{
				PosPayLoad: supl1.PosPayLoad{
					Choice:      supl1.PosPayLoadChoice_RrlpPayload,
					RrlpPayload: ptr([]byte{0x01, 0x02, 0x03, 0x04}),
				},
			},
		},
	}
	raw3, _ := supl1.Marshal(&pdu3)
	_ = pw.WriteTCPPacket(slpIP, setIP, 7275, 50001, raw3)

	// Message 4: SLP -> SET (SUPL END)
	pdu4 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: pdu2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLEND,
			MsSUPLEND: &supl1.SUPLEND{
				StatusCode: ptr(supl1.StatusCode_Unspecified),
			},
		},
	}
	raw4, _ := supl1.Marshal(&pdu4)
	_ = pw.WriteTCPPacket(slpIP, setIP, 7275, 50001, raw4)

	_ = f.Close()

	destPath := "supl_ni_flow.pcap"
	data, _ := os.ReadFile(pcapPath)
	_ = os.WriteFile(destPath, data, 0644)

	tsharkPath, err := exec.LookPath("tshark")
	if err != nil {
		t.Logf("tshark not found on PATH; generated %s", destPath)
		return
	}

	cmd := exec.Command(tsharkPath, "-r", pcapPath, "-V")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("tshark error: %v\n%s", err, out.String())
	}
	outStr := out.String()
	if strings.Contains(outStr, "Malformed Packet") || strings.Contains(outStr, "Expert Info (Error") {
		t.Fatalf("tshark detected errors in NI flow:\n%s", outStr)
	}
	t.Logf("tshark cleanly dissected full NI Immediate flow with 0 errors!")
}

// TestPCAP_EventTriggerFlow synthesizes a full Event Trigger Service PCAP
// and validates it against Wireshark's packet-ulp dissector.
func TestPCAP_EventTriggerFlow(t *testing.T) {
	pcapPath := filepath.Join(t.TempDir(), "supl_event_trigger_flow.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("failed to create pcap: %v", err)
	}
	defer f.Close()

	pw, err := pcap.NewWriter(f)
	if err != nil {
		t.Fatalf("failed to create pcap writer: %v", err)
	}

	slpIP := net.ParseIP("10.0.0.1")
	setIP := net.ParseIP("192.168.1.100")

	// 1. SUPL INIT (Triggered)
	pdu1 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SlpSessionID: &supl1.SlpSessionID{
				SessionID: []byte{1, 2, 3, 4},
				SlpId:     supl1.SLPAddress{Choice: supl1.SLPAddressChoice_FQDN, FQDN: ptr(supl1.FQDN("slp.net"))},
			},
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLINIT,
			MsSUPLINIT: &supl1.SUPLINIT{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
				SLPMode:   supl1.SLPMode_Proxy,
				Ver2SUPLINITExtension: &supl1.Ver2SUPLINITExtension{
					TriggerType: ptr(supl1.TriggerType_AreaEvent),
				},
			},
		},
	}
	raw1, _ := supl1.Marshal(&pdu1)
	_ = pw.WriteTCPPacket(slpIP, setIP, 7275, 50002, raw1)

	// 2. SUPL TRIGGERED START
	pdu2 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SetSessionID: &supl1.SetSessionID{
				SessionId: 2002,
				SetId:     supl1.SETId{Choice: supl1.SETIdChoice_Msisdn, Msisdn: ptr([]byte{1, 2, 3, 4, 5, 6, 7, 8})},
			},
			SlpSessionID: pdu1.SessionID.SlpSessionID,
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLTRIGGEREDSTART,
			MsSUPLTRIGGEREDSTART: &supl1.Ver2SUPLTRIGGEREDSTART{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{AgpsSETassisted: true},
					PrefMethod:    supl1.PrefMethod_NoPreference,
					PosProtocol:   supl1.PosProtocol{Rrlp: true},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice:  supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{RefMCC: 208, RefMNC: 10, RefLAC: 100, RefCI: 200},
					},
				},
				TriggerType: ptr(supl1.TriggerType_AreaEvent),
				TriggerParams: &supl1.TriggerParams{
					Choice: supl1.TriggerParamsChoice_AreaEventParams,
					AreaEventParams: &supl1.AreaEventParams{
						AreaEventType:    supl1.AreaEventType_EnteringArea,
						LocationEstimate: true,
					},
				},
			},
		},
	}
	raw2, _ := supl1.Marshal(&pdu2)
	_ = pw.WriteTCPPacket(setIP, slpIP, 50002, 7275, raw2)

	// 3. SUPL TRIGGERED RESPONSE
	pdu3 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: pdu2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLTRIGGEREDRESPONSE,
			MsSUPLTRIGGEREDRESPONSE: &supl1.Ver2SUPLTRIGGEREDRESPONSE{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
			},
		},
	}
	raw3, _ := supl1.Marshal(&pdu3)
	_ = pw.WriteTCPPacket(slpIP, setIP, 7275, 50002, raw3)

	// 4. SUPL REPORT
	pdu4 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: pdu2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLREPORT,
			MsSUPLREPORT: &supl1.Ver2SUPLREPORT{
				ReportDataList: &supl1.ReportDataList{
					{
						PositionData: &supl1.PositionData{
							Position: supl1.Position{
								Timestamp: "260928123000Z",
								PositionEstimate: supl1.PositionEstimate{
									LatitudeSign: supl1.PositionEstimateLatitudeSign_North,
									Latitude:     4885884,
									Longitude:    229435,
								},
							},
						},
					},
				},
			},
		},
	}
	raw4, _ := supl1.Marshal(&pdu4)
	_ = pw.WriteTCPPacket(setIP, slpIP, 50002, 7275, raw4)

	// 5. SUPL TRIGGERED STOP
	pdu5 := supl1.ULPPDU{
		Length: 0, Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: pdu2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLTRIGGEREDSTOP,
			MsSUPLTRIGGEREDSTOP: &supl1.Ver2SUPLTRIGGEREDSTOP{
				StatusCode: ptr(supl1.StatusCode_Ver2SessionStopped),
			},
		},
	}
	raw5, _ := supl1.Marshal(&pdu5)
	_ = pw.WriteTCPPacket(slpIP, setIP, 7275, 50002, raw5)

	_ = f.Close()

	destPath := "supl_event_trigger_flow.pcap"
	data, _ := os.ReadFile(pcapPath)
	_ = os.WriteFile(destPath, data, 0644)

	tsharkPath, err := exec.LookPath("tshark")
	if err != nil {
		t.Logf("tshark not found on PATH; generated %s", destPath)
		return
	}

	cmd := exec.Command(tsharkPath, "-r", pcapPath, "-V")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("tshark error: %v\n%s", err, out.String())
	}
	outStr := out.String()
	if strings.Contains(outStr, "Malformed Packet") || strings.Contains(outStr, "Expert Info (Error") {
		t.Fatalf("tshark detected errors in Event Trigger flow:\n%s", outStr)
	}
	t.Logf("tshark cleanly dissected full Event Trigger flow with 0 errors!")
}

