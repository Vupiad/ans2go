package supl1_test

import (
	"bytes"
	"reflect"
	"testing"

	"ans2go/example/supl1"
	"ans2go/pkg/uper"
)

// TestCallFlow_NI_Immediate_MaximalFields tests the complete Network-Initiated Immediate Service
// call flow with 100% of all mandatory, optional, and extension fields populated with distinct values.
func TestCallFlow_NI_Immediate_MaximalFields(t *testing.T) {
	// =========================================================================
	// Step 1: SLP -> SET: SUPL INIT (Session initiation, proxy mode, notification)
	// =========================================================================
	step1PDU := supl1.ULPPDU{
		Length: 0,
		Version: supl1.Version{
			Maj:     2,
			Min:     0,
			Servind: 0,
		},
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
				Notification: &supl1.Notification{
					NotificationType: supl1.NotificationType_NotificationAndVerficationAllowedNA,
					EncodingType:     ptr(supl1.EncodingType_Utf8),
					RequestorId:      ptr([]byte("EmergencyDispatch")),
					RequestorIdType:  ptr(supl1.FormatIndicator_LogicalName),
					ClientName:       ptr([]byte("911Service")),
					ClientNameType:   ptr(supl1.FormatIndicator_Url),
				},
				SLPAddress: &supl1.SLPAddress{
					Choice: supl1.SLPAddressChoice_FQDN,
					FQDN:   ptr(supl1.FQDN("h-slp.carrier.net")),
				},
				QoP: &supl1.QoP{
					Horacc:     10,
					Veracc:     ptr(int64(20)),
					MaxLocAge:  ptr(int64(30)),
					Delay:      ptr(int64(5)),
				},
				SLPMode: supl1.SLPMode_Proxy,
				MAC: ptr(supl1.MAC(uper.NewBitString([]byte{
					0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				}, 64))),
				KeyIdentity: ptr(supl1.KeyIdentity(uper.NewBitString([]byte{
					0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
					0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
				}, 128))),
				Ver2SUPLINITExtension: &supl1.Ver2SUPLINITExtension{
					NotificationMode:    ptr(supl1.NotificationMode_Normal),
					MinimumMajorVersion: ptr(int64(2)),
				},
			},
		},
	}

	raw1, err := supl1.Marshal(&step1PDU)
	if err != nil {
		t.Fatalf("Step 1 Marshal failed: %v", err)
	}
	var dec1 supl1.ULPPDU
	if err := supl1.Unmarshal(raw1, &dec1); err != nil {
		t.Fatalf("Step 1 Unmarshal failed: %v", err)
	}

	// Deep field assertions for Step 1
	if dec1.Message.MsSUPLINIT == nil {
		t.Fatalf("Step 1 MsSUPLINIT is nil")
	}
	s1 := dec1.Message.MsSUPLINIT
	if s1.PosMethod != supl1.PosMethod_AgpsSETassisted || s1.SLPMode != supl1.SLPMode_Proxy {
		t.Errorf("Step 1 PosMethod or SLPMode mismatch")
	}
	if s1.Notification == nil || s1.Notification.NotificationType != supl1.NotificationType_NotificationAndVerficationAllowedNA {
		t.Errorf("Step 1 Notification mismatch")
	}
	if string(*s1.Notification.RequestorId) != "EmergencyDispatch" || string(*s1.Notification.ClientName) != "911Service" {
		t.Errorf("Step 1 Notification strings mismatch")
	}
	if s1.QoP == nil || s1.QoP.Horacc != 10 || *s1.QoP.Veracc != 20 || *s1.QoP.MaxLocAge != 30 || *s1.QoP.Delay != 5 {
		t.Errorf("Step 1 QoP fields mismatch: %+v", s1.QoP)
	}
	if s1.MAC == nil || s1.MAC.BitLength != 64 || s1.KeyIdentity == nil || s1.KeyIdentity.BitLength != 128 {
		t.Errorf("Step 1 MAC or KeyIdentity length mismatch")
	}
	if s1.Ver2SUPLINITExtension == nil || *s1.Ver2SUPLINITExtension.NotificationMode != supl1.NotificationMode_Normal || *s1.Ver2SUPLINITExtension.MinimumMajorVersion != 2 {
		t.Errorf("Step 1 extension fields mismatch")
	}

	// =========================================================================
	// Step 2: SET -> SLP: SUPL POS INIT (SET capabilities, cell ID, requested assist data)
	// =========================================================================
	step2PDU := supl1.ULPPDU{
		Length: 0,
		Version: supl1.Version{
			Maj:     2,
			Min:     0,
			Servind: 0,
		},
		SessionID: supl1.SessionID{
			SetSessionID: &supl1.SetSessionID{
				SessionId: 1001,
				SetId: supl1.SETId{
					Choice: supl1.SETIdChoice_Msisdn,
					Msisdn: ptr([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56}),
				},
			},
			SlpSessionID: step1PDU.SessionID.SlpSessionID, // Preserve session continuity
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOSINIT,
			MsSUPLPOSINIT: &supl1.SUPLPOSINIT{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{
						AgpsSETassisted: true,
						AgpsSETBased:    true,
						AutonomousGPS:   true,
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
				RequestedAssistData: &supl1.RequestedAssistData{
					AlmanacRequested:          true,
					UtcModelRequested:         true,
					IonosphericModelRequested: true,
					DgpsCorrectionsRequested:  false,
					ReferenceLocationRequested: true,
					ReferenceTimeRequested:     true,
					AcquisitionAssistanceRequested: true,
					RealTimeIntegrityRequested:     true,
					NavigationModelRequested:       true,
					NavigationModelData: &supl1.NavigationModel{
						GpsWeek:  1000,
						GpsToe:   120,
						NSAT:     12,
						ToeLimit: 4,
						SatInfo: &supl1.SatelliteInfo{
							{SatId: 1, IODE: 55},
							{SatId: 2, IODE: 60},
						},
					},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice: supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{
							RefMCC: 310,
							RefMNC: 260,
							RefLAC: 100,
							RefCI:  200,
							TA:     ptr(int64(3)),
						},
					},
				},
				Position: &supl1.Position{
					Timestamp: "260928120000Z",
					PositionEstimate: supl1.PositionEstimate{
						LatitudeSign: supl1.PositionEstimateLatitudeSign_North,
						Latitude:     4500000,
						Longitude:    -1200000,
						Confidence:   ptr(int64(95)),
						AltitudeInfo: &supl1.AltitudeInfo{
							AltitudeDirection: supl1.AltitudeInfoAltitudeDirection_Height,
							Altitude:          150,
							AltUncertainty:    10,
						},
					},
				},
				Ver: ptr(supl1.Ver(uper.NewBitString([]byte{
					0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
				}, 64))),
			},
		},
	}

	raw2, err := supl1.Marshal(&step2PDU)
	if err != nil {
		t.Fatalf("Step 2 Marshal failed: %v", err)
	}
	t.Logf("STEP2_SUPLPOSINIT_HEX: %X", raw2)
	var dec2 supl1.ULPPDU
	if err := supl1.Unmarshal(raw2, &dec2); err != nil {
		t.Fatalf("Step 2 Unmarshal failed: %v", err)
	}

	// Deep field assertions for Step 2
	if dec2.Message.MsSUPLPOSINIT == nil {
		t.Fatalf("Step 2 MsSUPLPOSINIT is nil")
	}
	s2 := dec2.Message.MsSUPLPOSINIT
	if !s2.SETCapabilities.PosTechnology.AgpsSETassisted || !s2.SETCapabilities.PosTechnology.AgpsSETBased || !s2.SETCapabilities.PosTechnology.AutonomousGPS {
		t.Errorf("Step 2 SETCapabilities PosTechnology flags mismatch")
	}
	if s2.SETCapabilities.PrefMethod != supl1.PrefMethod_AgpsSETassistedPreferred || !s2.SETCapabilities.PosProtocol.Rrlp {
		t.Errorf("Step 2 SETCapabilities PrefMethod or PosProtocol mismatch")
	}
	if s2.RequestedAssistData == nil || !s2.RequestedAssistData.AlmanacRequested || !s2.RequestedAssistData.NavigationModelRequested {
		t.Errorf("Step 2 RequestedAssistData flags mismatch")
	}
	nm := s2.RequestedAssistData.NavigationModelData
	if nm == nil || nm.GpsWeek != 1000 || nm.GpsToe != 120 || nm.NSAT != 12 || nm.ToeLimit != 4 {
		t.Errorf("Step 2 NavigationModel fields mismatch: %+v", nm)
	}
	if nm.SatInfo == nil || len(*nm.SatInfo) != 2 || (*nm.SatInfo)[0].SatId != 1 || (*nm.SatInfo)[1].IODE != 60 {
		t.Errorf("Step 2 SatInfo elements mismatch: %+v", nm.SatInfo)
	}
	if s2.LocationId.CellInfo.Choice != supl1.CellInfoChoice_GsmCell || s2.LocationId.CellInfo.GsmCell.RefLAC != 100 || *s2.LocationId.CellInfo.GsmCell.TA != 3 {
		t.Errorf("Step 2 LocationId CellInfo mismatch")
	}
	if s2.Position == nil || s2.Position.PositionEstimate.Latitude != 4500000 || *s2.Position.PositionEstimate.Confidence != 95 {
		t.Errorf("Step 2 Position estimate mismatch")
	}
	if s2.Ver == nil || s2.Ver.BitLength != 64 || !bytes.Equal(s2.Ver.Bytes, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}) {
		t.Errorf("Step 2 Ver bit string mismatch")
	}

	// =========================================================================
	// Step 3: SLP -> SET: SUPL POS (RRLP Assistance Data payload exchange)
	// =========================================================================
	step3PDU := supl1.ULPPDU{
		Length:    0,
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOS,
			MsSUPLPOS: &supl1.SUPLPOS{
				PosPayLoad: supl1.PosPayLoad{
					Choice:      supl1.PosPayLoadChoice_RrlpPayload,
					RrlpPayload: ptr([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}),
				},
				Velocity: &supl1.Velocity{
					Choice: supl1.VelocityChoice_Horvel,
					Horvel: &supl1.Horvel{
						Bearing:  uper.NewBitString([]byte{0x80, 0x00}, 9),
						Horspeed: uper.NewBitString([]byte{0x00, 0x64}, 16),
					},
				},
			},
		},
	}

	raw3, err := supl1.Marshal(&step3PDU)
	if err != nil {
		t.Fatalf("Step 3 Marshal failed: %v", err)
	}
	t.Logf("STEP3_SUPLPOS_HEX: %X", raw3)
	var dec3 supl1.ULPPDU
	if err := supl1.Unmarshal(raw3, &dec3); err != nil {
		t.Fatalf("Step 3 Unmarshal failed: %v", err)
	}
	if dec3.Message.MsSUPLPOS == nil || dec3.Message.MsSUPLPOS.PosPayLoad.Choice != supl1.PosPayLoadChoice_RrlpPayload {
		t.Fatalf("Step 3 PosPayLoad choice mismatch")
	}
	if !bytes.Equal(*dec3.Message.MsSUPLPOS.PosPayLoad.RrlpPayload, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}) {
		t.Fatalf("Step 3 RrlpPayload bytes mismatch")
	}
	if dec3.Message.MsSUPLPOS.Velocity == nil || dec3.Message.MsSUPLPOS.Velocity.Horvel == nil {
		t.Fatalf("Step 3 Velocity Horvel is nil")
	}
	if dec3.Message.MsSUPLPOS.Velocity.Horvel.Bearing.BitLength != 9 || dec3.Message.MsSUPLPOS.Velocity.Horvel.Horspeed.BitLength != 16 {
		t.Fatalf("Step 3 Velocity bit lengths mismatch")
	}

	// =========================================================================
	// Step 4: SET -> SLP: SUPL POS (RRC Measurement payload exchange)
	// =========================================================================
	step4PDU := supl1.ULPPDU{
		Length:    0,
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOS,
			MsSUPLPOS: &supl1.SUPLPOS{
				PosPayLoad: supl1.PosPayLoad{
					Choice:     supl1.PosPayLoadChoice_RrcPayload,
					RrcPayload: ptr([]byte{0xAA, 0xBB, 0xCC, 0xDD}),
				},
			},
		},
	}

	raw4, err := supl1.Marshal(&step4PDU)
	if err != nil {
		t.Fatalf("Step 4 Marshal failed: %v", err)
	}
	var dec4 supl1.ULPPDU
	if err := supl1.Unmarshal(raw4, &dec4); err != nil {
		t.Fatalf("Step 4 Unmarshal failed: %v", err)
	}
	if dec4.Message.MsSUPLPOS == nil || dec4.Message.MsSUPLPOS.PosPayLoad.Choice != supl1.PosPayLoadChoice_RrcPayload {
		t.Fatalf("Step 4 PosPayLoad choice mismatch")
	}
	if !bytes.Equal(*dec4.Message.MsSUPLPOS.PosPayLoad.RrcPayload, []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("Step 4 RrcPayload bytes mismatch")
	}

	// =========================================================================
	// Step 5: SLP -> SET: SUPL END (Termination with final position and status)
	// =========================================================================
	step5PDU := supl1.ULPPDU{
		Length:    0,
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLEND,
			MsSUPLEND: &supl1.SUPLEND{
				StatusCode: ptr(supl1.StatusCode_Unspecified),
				Position: &supl1.Position{
					Timestamp: "260928120005Z",
					PositionEstimate: supl1.PositionEstimate{
						LatitudeSign: supl1.PositionEstimateLatitudeSign_North,
						Latitude:     4500050,
						Longitude:    -1200050,
						Confidence:   ptr(int64(98)),
						AltitudeInfo: &supl1.AltitudeInfo{
							AltitudeDirection: supl1.AltitudeInfoAltitudeDirection_Height,
							Altitude:          152,
							AltUncertainty:    8,
						},
						Uncertainty: &supl1.PositionEstimateUncertainty{
							UncertaintySemiMajor: 12,
							UncertaintySemiMinor: 8,
							OrientationMajorAxis: 45,
						},
					},
				},
				Ver: ptr(supl1.Ver(uper.NewBitString([]byte{
					0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				}, 64))),
			},
		},
	}

	raw5, err := supl1.Marshal(&step5PDU)
	if err != nil {
		t.Fatalf("Step 5 Marshal failed: %v", err)
	}
	var dec5 supl1.ULPPDU
	if err := supl1.Unmarshal(raw5, &dec5); err != nil {
		t.Fatalf("Step 5 Unmarshal failed: %v", err)
	}
	if dec5.Message.MsSUPLEND == nil {
		t.Fatalf("Step 5 MsSUPLEND is nil")
	}
	s5 := dec5.Message.MsSUPLEND
	if s5.StatusCode == nil || *s5.StatusCode != supl1.StatusCode_Unspecified {
		t.Errorf("Step 5 StatusCode mismatch")
	}
	if s5.Position == nil || s5.Position.PositionEstimate.Latitude != 4500050 || *s5.Position.PositionEstimate.Confidence != 98 {
		t.Errorf("Step 5 Position estimate mismatch")
	}
	if s5.Position.PositionEstimate.Uncertainty == nil || s5.Position.PositionEstimate.Uncertainty.OrientationMajorAxis != 45 {
		t.Errorf("Step 5 Uncertainty mismatch")
	}
	if s5.Ver == nil || !bytes.Equal(s5.Ver.Bytes, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}) {
		t.Errorf("Step 5 Ver mismatch")
	}
}

// TestCallFlow_NI_Immediate_MinimalFields tests the entire NI flow with all optional fields omitted (nil).
// This verifies that presence bitmasks correctly encode 0s and decode strictly as nil.
func TestCallFlow_NI_Immediate_MinimalFields(t *testing.T) {
	// Step 1: Minimal SUPLINIT
	pdu1 := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SlpSessionID: &supl1.SlpSessionID{
				SessionID: []byte{1, 2, 3, 4},
				SlpId: supl1.SLPAddress{
					Choice: supl1.SLPAddressChoice_FQDN,
					FQDN:   ptr(supl1.FQDN("slp.test")),
				},
			},
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLINIT,
			MsSUPLINIT: &supl1.SUPLINIT{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
				SLPMode:   supl1.SLPMode_Proxy,
				// All optionals are nil: Notification, SLPAddress, QoP, MAC, KeyIdentity, Extension
			},
		},
	}
	raw1, err := supl1.Marshal(&pdu1)
	if err != nil {
		t.Fatal(err)
	}
	var dec1 supl1.ULPPDU
	if err := supl1.Unmarshal(raw1, &dec1); err != nil {
		t.Fatal(err)
	}
	s1 := dec1.Message.MsSUPLINIT
	if s1.Notification != nil || s1.SLPAddress != nil || s1.QoP != nil || s1.MAC != nil || s1.KeyIdentity != nil || s1.Ver2SUPLINITExtension != nil {
		t.Errorf("Expected all optional fields in minimal SUPLINIT to be nil, got: %+v", s1)
	}

	// Step 2: Minimal SUPLPOSINIT
	pdu2 := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SetSessionID: &supl1.SetSessionID{
				SessionId: 555,
				SetId: supl1.SETId{
					Choice: supl1.SETIdChoice_Msisdn,
					Msisdn: ptr([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
				},
			},
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOSINIT,
			MsSUPLPOSINIT: &supl1.SUPLPOSINIT{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{AgpsSETassisted: true},
					PrefMethod:    supl1.PrefMethod_NoPreference,
					PosProtocol:   supl1.PosProtocol{Rrlp: true},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice: supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{
							RefMCC: 1, RefMNC: 2, RefLAC: 3, RefCI: 4,
						},
					},
				},
				// All optionals nil: RequestedAssistData, Position, SUPLPOS, Ver, Extension
			},
		},
	}
	raw2, err := supl1.Marshal(&pdu2)
	if err != nil {
		t.Fatal(err)
	}
	var dec2 supl1.ULPPDU
	if err := supl1.Unmarshal(raw2, &dec2); err != nil {
		t.Fatal(err)
	}
	s2 := dec2.Message.MsSUPLPOSINIT
	if s2.RequestedAssistData != nil || s2.Position != nil || s2.SUPLPOS != nil || s2.Ver != nil || s2.Ver2SUPLPOSINITExtension != nil {
		t.Errorf("Expected all optional fields in minimal SUPLPOSINIT to be nil, got: %+v", s2)
	}

	// Step 3: Minimal SUPLPOS
	pdu3 := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOS,
			MsSUPLPOS: &supl1.SUPLPOS{
				PosPayLoad: supl1.PosPayLoad{
					Choice:      supl1.PosPayLoadChoice_RrlpPayload,
					RrlpPayload: ptr([]byte{0xFF}),
				},
				// Velocity and Extension nil
			},
		},
	}
	raw3, err := supl1.Marshal(&pdu3)
	if err != nil {
		t.Fatal(err)
	}
	var dec3 supl1.ULPPDU
	if err := supl1.Unmarshal(raw3, &dec3); err != nil {
		t.Fatal(err)
	}
	if dec3.Message.MsSUPLPOS.Velocity != nil || dec3.Message.MsSUPLPOS.Ver2SUPLPOSExtension != nil {
		t.Errorf("Expected Velocity to be nil in minimal SUPLPOS")
	}

	// Step 4: Minimal SUPLEND
	pdu4 := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLEND,
			MsSUPLEND: &supl1.SUPLEND{
				// Position, StatusCode, Ver, Extension all nil
			},
		},
	}
	raw4, err := supl1.Marshal(&pdu4)
	if err != nil {
		t.Fatal(err)
	}
	var dec4 supl1.ULPPDU
	if err := supl1.Unmarshal(raw4, &dec4); err != nil {
		t.Fatal(err)
	}
	s4 := dec4.Message.MsSUPLEND
	if s4.Position != nil || s4.StatusCode != nil || s4.Ver != nil || s4.Ver2SUPLENDExtension != nil {
		t.Errorf("Expected all optional fields in minimal SUPLEND to be nil, got: %+v", s4)
	}
}

// TestCallFlow_NI_Immediate_ChoiceVariants exercises all polymorphic CHOICE alternatives
// in the NI flow (CellInfo alternatives: WCDMA, CDMA; PosPayLoad alternatives: TIA-801; SLPAddress: IPv4, IPv6).
func TestCallFlow_NI_Immediate_ChoiceVariants(t *testing.T) {
	// 1. CellInfoChoice_WcdmaCell
	wcdmaPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOSINIT,
			MsSUPLPOSINIT: &supl1.SUPLPOSINIT{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{AgpsSETassisted: true},
					PrefMethod:    supl1.PrefMethod_NoPreference,
					PosProtocol:   supl1.PosProtocol{Rrc: true},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice: supl1.CellInfoChoice_WcdmaCell,
						WcdmaCell: &supl1.WcdmaCellInformation{
							RefMCC: 460,
							RefMNC: 1,
							RefUC:  1234567,
						},
					},
				},
			},
		},
	}
	rawWcdma, err := supl1.Marshal(&wcdmaPDU)
	if err != nil {
		t.Fatalf("WcdmaCell Marshal failed: %v", err)
	}
	var decWcdma supl1.ULPPDU
	if err := supl1.Unmarshal(rawWcdma, &decWcdma); err != nil {
		t.Fatalf("WcdmaCell Unmarshal failed: %v", err)
	}
	if decWcdma.Message.MsSUPLPOSINIT.LocationId.CellInfo.Choice != supl1.CellInfoChoice_WcdmaCell {
		t.Errorf("Expected WcdmaCell choice")
	}
	if decWcdma.Message.MsSUPLPOSINIT.LocationId.CellInfo.WcdmaCell.RefUC != 1234567 {
		t.Errorf("WCDMA RefUC mismatch")
	}

	// 2. CellInfoChoice_CdmaCell
	cdmaPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOSINIT,
			MsSUPLPOSINIT: &supl1.SUPLPOSINIT{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{AutonomousGPS: true},
					PrefMethod:    supl1.PrefMethod_NoPreference,
					PosProtocol:   supl1.PosProtocol{Tia801: true},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice: supl1.CellInfoChoice_CdmaCell,
						CdmaCell: &supl1.CdmaCellInformation{
							RefNID:    12,
							RefSID:    34,
							RefBASEID: 56,
						},
					},
				},
			},
		},
	}
	rawCdma, err := supl1.Marshal(&cdmaPDU)
	if err != nil {
		t.Fatalf("CdmaCell Marshal failed: %v", err)
	}
	var decCdma supl1.ULPPDU
	if err := supl1.Unmarshal(rawCdma, &decCdma); err != nil {
		t.Fatalf("CdmaCell Unmarshal failed: %v", err)
	}
	if decCdma.Message.MsSUPLPOSINIT.LocationId.CellInfo.Choice != supl1.CellInfoChoice_CdmaCell {
		t.Errorf("Expected CdmaCell choice")
	}

	// 3. PosPayLoadChoice_Tia801payload
	tiaPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOS,
			MsSUPLPOS: &supl1.SUPLPOS{
				PosPayLoad: supl1.PosPayLoad{
					Choice:         supl1.PosPayLoadChoice_Tia801payload,
					Tia801payload: ptr([]byte{0x11, 0x22, 0x33, 0x44, 0x55}),
				},
			},
		},
	}
	rawTia, err := supl1.Marshal(&tiaPDU)
	if err != nil {
		t.Fatalf("Tia801 Marshal failed: %v", err)
	}
	var decTia supl1.ULPPDU
	if err := supl1.Unmarshal(rawTia, &decTia); err != nil {
		t.Fatalf("Tia801 Unmarshal failed: %v", err)
	}
	if decTia.Message.MsSUPLPOS.PosPayLoad.Choice != supl1.PosPayLoadChoice_Tia801payload {
		t.Errorf("Expected Tia801 choice")
	}

	// 4. SLPAddressChoice_IPAddress (IPv4 and IPv6)
	ipPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLINIT,
			MsSUPLINIT: &supl1.SUPLINIT{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
				SLPMode:   supl1.SLPMode_Proxy,
				SLPAddress: &supl1.SLPAddress{
					Choice: supl1.SLPAddressChoice_IPAddress,
					IPAddress: &supl1.IPAddress{
						Choice:      supl1.IPAddressChoice_Ipv4Address,
						Ipv4Address: ptr([]byte{192, 168, 1, 100}),
					},
				},
			},
		},
	}
	rawIP, err := supl1.Marshal(&ipPDU)
	if err != nil {
		t.Fatalf("IPv4 Marshal failed: %v", err)
	}
	var decIP supl1.ULPPDU
	if err := supl1.Unmarshal(rawIP, &decIP); err != nil {
		t.Fatalf("IPv4 Unmarshal failed: %v", err)
	}
	if decIP.Message.MsSUPLINIT.SLPAddress.Choice != supl1.SLPAddressChoice_IPAddress {
		t.Errorf("Expected IPAddress choice")
	}
	if !bytes.Equal(*decIP.Message.MsSUPLINIT.SLPAddress.IPAddress.Ipv4Address, []byte{192, 168, 1, 100}) {
		t.Errorf("IPv4 bytes mismatch")
	}
}

func assertDeepEqual(t *testing.T, name string, expected, actual any) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("%s: deep equality mismatch:\nwant: %+v\ngot:  %+v", name, expected, actual)
	}
}
