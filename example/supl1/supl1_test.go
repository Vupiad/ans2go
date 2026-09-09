package supl1

import (
	"bytes"
	"testing"
)

func ptr[T any](v T) *T {
	return &v
}

func TestSuplInitRoundtrip(t *testing.T) {
	pdu := ULPPDU{
		Length: 0,
		Version: Version{
			Maj:     2,
			Min:     0,
			Servind: 0,
		},
		SessionID: SessionID{
			SlpSessionID: &SlpSessionID{
				SessionID: []byte{0xDE, 0xAD, 0xBE, 0xEF},
				SlpId: SLPAddress{
					Choice: SLPAddressChoice_FQDN,
					FQDN:   ptr(FQDN("slp.carrier.net")),
				},
			},
		},
		Message: UlpMessage{
			Choice: UlpMessageChoice_MsSUPLINIT,
			MsSUPLINIT: &SUPLINIT{
				PosMethod: PosMethod_AgpsSETassisted,
				SLPMode:   SLPMode_Proxy,
				Notification: &Notification{
					NotificationType: NotificationType_NotificationOnly,
					EncodingType:     ptr(EncodingType_Utf8),
					RequestorId:      ptr([]byte("EmergencyCenter")),
				},
			},
		},
	}

	data, err := Marshal(&pdu)
	if err != nil {
		t.Fatalf("Marshal SUPLINIT failed: %v", err)
	}

	t.Logf("Encoded SUPLINIT (%d bytes): %X", len(data), data)

	var decoded ULPPDU
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal SUPLINIT failed: %v", err)
	}

	// Verify decoded fields
	if decoded.Version.Maj != 2 || decoded.Version.Min != 0 {
		t.Fatalf("version mismatch: %v", decoded.Version)
	}
	if decoded.SessionID.SlpSessionID == nil || !bytes.Equal(decoded.SessionID.SlpSessionID.SessionID, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("slpSessionID mismatch")
	}
	if *decoded.SessionID.SlpSessionID.SlpId.FQDN != "slp.carrier.net" {
		t.Fatalf("fqdn mismatch: %s", *decoded.SessionID.SlpSessionID.SlpId.FQDN)
	}
	if decoded.Message.Choice != UlpMessageChoice_MsSUPLINIT {
		t.Fatalf("choice mismatch")
	}
	initMsg := decoded.Message.MsSUPLINIT
	if initMsg.PosMethod != PosMethod_AgpsSETassisted || initMsg.SLPMode != SLPMode_Proxy {
		t.Fatalf("posMethod or slpMode mismatch")
	}
	if initMsg.Notification == nil || initMsg.Notification.NotificationType != NotificationType_NotificationOnly {
		t.Fatalf("notification mismatch")
	}
	if string(*initMsg.Notification.RequestorId) != "EmergencyCenter" {
		t.Fatalf("requestorId mismatch: %s", string(*initMsg.Notification.RequestorId))
	}
}

func TestSuplStartRoundtrip(t *testing.T) {
	pdu := ULPPDU{
		Length: 0,
		Version: Version{
			Maj:     2,
			Min:     0,
			Servind: 0,
		},
		SessionID: SessionID{
			SetSessionID: &SetSessionID{
				SessionId: 4321,
				SetId: SETId{
					Choice: SETIdChoice_Msisdn,
					Msisdn: ptr([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}),
				},
			},
		},
		Message: UlpMessage{
			Choice: UlpMessageChoice_MsSUPLSTART,
			MsSUPLSTART: &SUPLSTART{
				SETCapabilities: SETCapabilities{
					PosTechnology: PosTechnology{
						AgpsSETassisted: true,
						AgpsSETBased:    false,
						AutonomousGPS:   true,
						AFLT:            false,
						ECID:            false,
						EOTD:            false,
						OTDOA:           false,
					},
					PrefMethod: PrefMethod_AgpsSETassistedPreferred,
					PosProtocol: PosProtocol{
						Tia801: false,
						Rrlp:   true,
						Rrc:    false,
					},
				},
				LocationId: LocationId{
					Status: Status_Current,
					CellInfo: CellInfo{
						Choice: CellInfoChoice_GsmCell,
						GsmCell: &GsmCellInformation{
							RefMCC: 460,
							RefMNC: 1,
							RefLAC: 1024,
							RefCI:  2048,
							TA:     ptr(int64(5)),
						},
					},
				},
			},
		},
	}

	data, err := Marshal(&pdu)
	if err != nil {
		t.Fatalf("Marshal SUPLSTART failed: %v", err)
	}

	t.Logf("Encoded SUPLSTART (%d bytes): %X", len(data), data)

	var decoded ULPPDU
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal SUPLSTART failed: %v", err)
	}

	if decoded.SessionID.SetSessionID == nil || decoded.SessionID.SetSessionID.SessionId != 4321 {
		t.Fatalf("SetSessionID mismatch")
	}
	if !bytes.Equal(*decoded.SessionID.SetSessionID.SetId.Msisdn, []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}) {
		t.Fatalf("msisdn mismatch")
	}

	startMsg := decoded.Message.MsSUPLSTART
	if startMsg == nil {
		t.Fatalf("SUPLSTART is nil")
	}
	if !startMsg.SETCapabilities.PosTechnology.AgpsSETassisted || !startMsg.SETCapabilities.PosTechnology.AutonomousGPS {
		t.Fatalf("PosTechnology mismatch")
	}
	if startMsg.LocationId.CellInfo.Choice != CellInfoChoice_GsmCell {
		t.Fatalf("cellInfo choice mismatch")
	}
	gsm := startMsg.LocationId.CellInfo.GsmCell
	if gsm.RefMCC != 460 || gsm.RefMNC != 1 || gsm.RefLAC != 1024 || gsm.RefCI != 2048 {
		t.Fatalf("gsm cell mismatch: %v", gsm)
	}
	if gsm.TA == nil || *gsm.TA != 5 {
		t.Fatalf("gsm TA mismatch")
	}
}

func TestSuplEndRoundtrip(t *testing.T) {
	pdu := ULPPDU{
		Length: 0,
		Version: Version{
			Maj:     2,
			Min:     0,
			Servind: 0,
		},
		SessionID: SessionID{
			SetSessionID: &SetSessionID{
				SessionId: 9999,
				SetId: SETId{
					Choice: SETIdChoice_Nai,
					Nai:    ptr("user@domain.com"),
				},
			},
		},
		Message: UlpMessage{
			Choice: UlpMessageChoice_MsSUPLEND,
			MsSUPLEND: &SUPLEND{
				StatusCode: ptr(StatusCode_ConsentDeniedByUser),
			},
		},
	}

	data, err := Marshal(&pdu)
	if err != nil {
		t.Fatalf("Marshal SUPLEND failed: %v", err)
	}

	t.Logf("Encoded SUPLEND (%d bytes): %X", len(data), data)

	var decoded ULPPDU
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal SUPLEND failed: %v", err)
	}

	if decoded.Message.MsSUPLEND == nil {
		t.Fatalf("SUPLEND is nil")
	}
	if decoded.Message.MsSUPLEND.StatusCode == nil || *decoded.Message.MsSUPLEND.StatusCode != StatusCode_ConsentDeniedByUser {
		t.Fatalf("statusCode mismatch: %v", decoded.Message.MsSUPLEND.StatusCode)
	}
	if *decoded.SessionID.SetSessionID.SetId.Nai != "user@domain.com" {
		t.Fatalf("NAI mismatch")
	}
}

func TestPositionEstimateRoundtrip(t *testing.T) {
	pos := Position{
		Timestamp: "260909095144Z",
		PositionEstimate: PositionEstimate{
			LatitudeSign: PositionEstimateLatitudeSign_North,
			Latitude:     4500000,
			Longitude:    -1200000,
			Confidence:   ptr(int64(95)),
			AltitudeInfo: &AltitudeInfo{
				AltitudeDirection: AltitudeInfoAltitudeDirection_Height,
				Altitude:          150,
				AltUncertainty:    10,
			},
			Uncertainty: &PositionEstimateUncertainty{
				UncertaintySemiMajor: 20,
				UncertaintySemiMinor: 15,
				OrientationMajorAxis: 90,
			},
		},
	}

	data, err := Marshal(&pos)
	if err != nil {
		t.Fatalf("Marshal Position failed: %v", err)
	}

	var decoded Position
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal Position failed: %v", err)
	}

	if decoded.Timestamp != "260909095144Z" {
		t.Fatalf("timestamp mismatch: %s", decoded.Timestamp)
	}
	pe := decoded.PositionEstimate
	if pe.LatitudeSign != PositionEstimateLatitudeSign_North || pe.Latitude != 4500000 || pe.Longitude != -1200000 {
		t.Fatalf("position coordinates mismatch")
	}
	if pe.Confidence == nil || *pe.Confidence != 95 {
		t.Fatalf("confidence mismatch")
	}
	if pe.AltitudeInfo == nil || pe.AltitudeInfo.Altitude != 150 {
		t.Fatalf("altitude mismatch")
	}
	if pe.Uncertainty == nil || pe.Uncertainty.OrientationMajorAxis != 90 {
		t.Fatalf("uncertainty mismatch")
	}
}

func TestSequenceOfRoundtrip(t *testing.T) {
	locList := MultipleLocationIds{
		LocationIdData{
			LocationId: LocationId{
				Status: Status_Current,
				CellInfo: CellInfo{
					Choice: CellInfoChoice_GsmCell,
					GsmCell: &GsmCellInformation{
						RefMCC: 310,
						RefMNC: 260,
						RefLAC: 500,
						RefCI:  600,
					},
				},
			},
			ServingFlag: true,
		},
		LocationIdData{
			LocationId: LocationId{
				Status: Status_Stale,
				CellInfo: CellInfo{
					Choice: CellInfoChoice_GsmCell,
					GsmCell: &GsmCellInformation{
						RefMCC: 310,
						RefMNC: 260,
						RefLAC: 501,
						RefCI:  601,
					},
				},
			},
			ServingFlag: false,
		},
	}

	data, err := Marshal(&locList)
	if err != nil {
		t.Fatalf("Marshal MultipleLocationIds failed: %v", err)
	}

	var decoded MultipleLocationIds
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal MultipleLocationIds failed: %v", err)
	}

	if len(decoded) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(decoded))
	}
	if decoded[0].LocationId.CellInfo.GsmCell.RefLAC != 500 || decoded[1].LocationId.CellInfo.GsmCell.RefLAC != 501 {
		t.Fatalf("elements mismatch")
	}
	if !decoded[0].ServingFlag || decoded[1].ServingFlag {
		t.Fatalf("servingFlag mismatch")
	}
}

func TestSuplInitWithExtension(t *testing.T) {
	// Tests SEQUENCE extension additions (ver2-SUPL-INIT-extension in SUPLINIT)
	pdu := ULPPDU{
		Version: Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: SessionID{
			SlpSessionID: &SlpSessionID{
				SessionID: []byte{1, 2, 3, 4},
				SlpId: SLPAddress{
					Choice: SLPAddressChoice_IPAddress,
					IPAddress: &IPAddress{
						Choice:      IPAddressChoice_Ipv4Address,
						Ipv4Address: ptr([]byte{127, 0, 0, 1}),
					},
				},
			},
		},
		Message: UlpMessage{
			Choice: UlpMessageChoice_MsSUPLINIT,
			MsSUPLINIT: &SUPLINIT{
				PosMethod: PosMethod_AgpsSETassisted,
				SLPMode:   SLPMode_Proxy,
				Ver2SUPLINITExtension: &Ver2SUPLINITExtension{
					NotificationMode: ptr(NotificationMode_Normal),
				},
			},
		},
	}

	data, err := Marshal(&pdu)
	if err != nil {
		t.Fatalf("Marshal with extension failed: %v", err)
	}

	var decoded ULPPDU
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal with extension failed: %v", err)
	}

	initMsg := decoded.Message.MsSUPLINIT
	if initMsg.Ver2SUPLINITExtension == nil {
		t.Fatalf("expected Ver2SUPLINITExtension to be present")
	}
	if initMsg.Ver2SUPLINITExtension.NotificationMode == nil || *initMsg.Ver2SUPLINITExtension.NotificationMode != NotificationMode_Normal {
		t.Fatalf("notificationMode mismatch: %v", initMsg.Ver2SUPLINITExtension.NotificationMode)
	}
}

func TestSuplChoiceExtension(t *testing.T) {
	// Tests CHOICE extension alternatives (msSUPLTRIGGEREDSTART in UlpMessage is an extension choice)
	pdu := ULPPDU{
		Version: Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: SessionID{
			SetSessionID: &SetSessionID{
				SessionId: 777,
				SetId: SETId{
					Choice: SETIdChoice_Msisdn,
					Msisdn: ptr([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
				},
			},
		},
		Message: UlpMessage{
			Choice: UlpMessageChoice_MsSUPLTRIGGEREDSTART,
			MsSUPLTRIGGEREDSTART: &Ver2SUPLTRIGGEREDSTART{
				SETCapabilities: SETCapabilities{
					PosTechnology: PosTechnology{AgpsSETassisted: true},
					PrefMethod:    PrefMethod_AgpsSETassistedPreferred,
					PosProtocol:   PosProtocol{Rrlp: true},
				},
				LocationId: LocationId{
					Status: Status_Current,
					CellInfo: CellInfo{
						Choice: CellInfoChoice_GsmCell,
						GsmCell: &GsmCellInformation{
							RefMCC: 208,
							RefMNC: 10,
							RefLAC: 100,
							RefCI:  200,
						},
					},
				},
				TriggerType: ptr(TriggerType_Periodic),
				TriggerParams: &TriggerParams{
					Choice: TriggerParamsChoice_PeriodicParams,
					PeriodicParams: &PeriodicParams{
						NumberOfFixes: 10,
						IntervalBetweenFixes: 30,
					},
				},
			},
		},
	}

	data, err := Marshal(&pdu)
	if err != nil {
		t.Fatalf("Marshal choice extension failed: %v", err)
	}

	var decoded ULPPDU
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal choice extension failed: %v", err)
	}

	if decoded.Message.Choice != UlpMessageChoice_MsSUPLTRIGGEREDSTART {
		t.Fatalf("expected choice MsSUPLTRIGGEREDSTART, got %v", decoded.Message.Choice)
	}
	trigStart := decoded.Message.MsSUPLTRIGGEREDSTART
	if trigStart == nil {
		t.Fatalf("MsSUPLTRIGGEREDSTART is nil")
	}
	if trigStart.TriggerType == nil || *trigStart.TriggerType != TriggerType_Periodic {
		t.Fatalf("triggerType mismatch: %v", trigStart.TriggerType)
	}
	if trigStart.TriggerParams == nil || trigStart.TriggerParams.Choice != TriggerParamsChoice_PeriodicParams {
		t.Fatalf("triggerParams choice mismatch")
	}
	if trigStart.TriggerParams.PeriodicParams.NumberOfFixes != 10 || trigStart.TriggerParams.PeriodicParams.IntervalBetweenFixes != 30 {
		t.Fatalf("periodicParams mismatch: %v", trigStart.TriggerParams.PeriodicParams)
	}
}

