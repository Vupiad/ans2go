package supl1_test

import (
	"bytes"
	"testing"

	"ans2go/example/supl1"
	"ans2go/pkg/uper"
)

// TestCallFlow_EventTrigger_MaximalFields verifies the complete Event Trigger Service call flow (SUPL 2.0)
// with 100% of all fields (mandatory, optional, choice alternatives, and extension additions) populated.
func TestCallFlow_EventTrigger_MaximalFields(t *testing.T) {
	// =========================================================================
	// Step 1: SLP -> SET: SUPL INIT (Triggered initiation with Ver2 extensions)
	// =========================================================================
	step1PDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SlpSessionID: &supl1.SlpSessionID{
				SessionID: []byte{0xEE, 0x11, 0x22, 0x33},
				SlpId: supl1.SLPAddress{
					Choice: supl1.SLPAddressChoice_FQDN,
					FQDN:   ptr(supl1.FQDN("slp.trigger.net")),
				},
			},
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLINIT,
			MsSUPLINIT: &supl1.SUPLINIT{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
				SLPMode:   supl1.SLPMode_Proxy,
				Ver2SUPLINITExtension: &supl1.Ver2SUPLINITExtension{
					TriggerType:      ptr(supl1.TriggerType_AreaEvent),
					NotificationMode: ptr(supl1.NotificationMode_Normal),
					HistoricReporting: &supl1.HistoricReporting{
						AllowedReportingType: supl1.AllowedReportingType_PositionsOnly,
						ReportingCriteria: &supl1.ReportingCriteria{
							MaxNumberofReports: ptr(int64(100)),
							MinTimeInterval:    ptr(int64(10)),
						},
					},
					ProtectionLevel: &supl1.ProtectionLevel{
						Protlevel: supl1.ProtLevel_NullProtection,
					},
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
	s1 := dec1.Message.MsSUPLINIT
	if s1 == nil || s1.Ver2SUPLINITExtension == nil {
		t.Fatalf("Step 1 Ver2SUPLINITExtension is nil")
	}
	if *s1.Ver2SUPLINITExtension.TriggerType != supl1.TriggerType_AreaEvent {
		t.Errorf("Step 1 TriggerType mismatch")
	}
	if s1.Ver2SUPLINITExtension.HistoricReporting == nil || s1.Ver2SUPLINITExtension.HistoricReporting.AllowedReportingType != supl1.AllowedReportingType_PositionsOnly {
		t.Errorf("Step 1 HistoricReporting mismatch")
	}

	// =========================================================================
	// Step 2: SET -> SLP: SUPL TRIGGERED START (AreaEventParams, Location, SETCapabilities)
	// =========================================================================
	step2PDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: supl1.SessionID{
			SetSessionID: &supl1.SetSessionID{
				SessionId: 2002,
				SetId: supl1.SETId{
					Choice: supl1.SETIdChoice_Msisdn,
					Msisdn: ptr([]byte{0x98, 0x76, 0x54, 0x32, 0x10, 0x98, 0x76, 0x54}),
				},
			},
			SlpSessionID: step1PDU.SessionID.SlpSessionID,
		},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLTRIGGEREDSTART,
			MsSUPLTRIGGEREDSTART: &supl1.Ver2SUPLTRIGGEREDSTART{
				SETCapabilities: supl1.SETCapabilities{
					PosTechnology: supl1.PosTechnology{
						AgpsSETassisted: true,
						AutonomousGPS:   true,
					},
					PrefMethod: supl1.PrefMethod_AgpsSETassistedPreferred,
					PosProtocol: supl1.PosProtocol{
						Rrlp: true,
					},
				},
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice: supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{
							RefMCC: 208, RefMNC: 10, RefLAC: 100, RefCI: 200,
						},
					},
				},
				Ver: ptr(supl1.Ver(uper.NewBitString([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 64))),
				QoP: &supl1.QoP{
					Horacc: 15,
				},
				TriggerType: ptr(supl1.TriggerType_AreaEvent),
				TriggerParams: &supl1.TriggerParams{
					Choice: supl1.TriggerParamsChoice_AreaEventParams,
					AreaEventParams: &supl1.AreaEventParams{
						AreaEventType:    supl1.AreaEventType_EnteringArea,
						LocationEstimate: true,
						RepeatedReportingParams: &supl1.RepeatedReportingParams{
							MinimumIntervalTime:    60,
							MaximumNumberOfReports: 10,
						},
						StartTime: ptr(int64(0)),
						StopTime:  ptr(int64(3600)),
					},
				},
				CauseCode: ptr(supl1.CauseCode_ServingNetWorkNotInAreaIdList),
			},
		},
	}

	raw2, err := supl1.Marshal(&step2PDU)
	if err != nil {
		t.Fatalf("Step 2 Marshal failed: %v", err)
	}
	t.Logf("EVENT_STEP2_TRIGGEREDSTART_HEX: %X", raw2)
	var dec2 supl1.ULPPDU
	if err := supl1.Unmarshal(raw2, &dec2); err != nil {
		t.Fatalf("Step 2 Unmarshal failed: %v", err)
	}
	s2 := dec2.Message.MsSUPLTRIGGEREDSTART
	if s2 == nil || s2.TriggerParams == nil || s2.TriggerParams.Choice != supl1.TriggerParamsChoice_AreaEventParams {
		t.Fatalf("Step 2 AreaEventParams mismatch")
	}
	aep := s2.TriggerParams.AreaEventParams
	if aep.AreaEventType != supl1.AreaEventType_EnteringArea || !aep.LocationEstimate {
		t.Errorf("Step 2 AreaEventType or LocationEstimate mismatch")
	}
	if aep.RepeatedReportingParams == nil || aep.RepeatedReportingParams.MinimumIntervalTime != 60 || aep.RepeatedReportingParams.MaximumNumberOfReports != 10 {
		t.Errorf("Step 2 RepeatedReportingParams mismatch")
	}
	if s2.CauseCode == nil || *s2.CauseCode != supl1.CauseCode_ServingNetWorkNotInAreaIdList {
		t.Errorf("Step 2 CauseCode mismatch")
	}

	// =========================================================================
	// Step 3: SLP -> SET: SUPL TRIGGERED RESPONSE (ReportingMode, PosMethod, GNSS tech)
	// =========================================================================
	step3PDU := supl1.ULPPDU{
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLTRIGGEREDRESPONSE,
			MsSUPLTRIGGEREDRESPONSE: &supl1.Ver2SUPLTRIGGEREDRESPONSE{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
				ReportingMode: &supl1.ReportingMode{
					RepMode: supl1.RepMode_Batch,
					BatchRepConditions: &supl1.BatchRepConditions{
						Choice:      supl1.BatchRepConditionsChoice_NumInterval,
						NumInterval: ptr(int64(5)),
					},
					BatchRepType: &supl1.BatchRepType{
						ReportPosition:      true,
						ReportMeasurements:  false,
						IntermediateReports: false,
						DiscardOldest:       ptr(true),
					},
				},
				GnssPosTechnology: &supl1.GNSSPosTechnology{
					Gps:           true,
					Glonass:       false,
					Sbas:          false,
					ModernizedGps: false,
					Qzss:          false,
					Galileo:       true,
				},
			},
		},
	}

	raw3, err := supl1.Marshal(&step3PDU)
	if err != nil {
		t.Fatalf("Step 3 Marshal failed: %v", err)
	}
	t.Logf("EVENT_STEP3_TRIGGEREDRESPONSE_HEX: %X", raw3)
	var dec3 supl1.ULPPDU
	if err := supl1.Unmarshal(raw3, &dec3); err != nil {
		t.Fatalf("Step 3 Unmarshal failed: %v", err)
	}
	s3 := dec3.Message.MsSUPLTRIGGEREDRESPONSE
	if s3 == nil || s3.ReportingMode == nil || s3.ReportingMode.RepMode != supl1.RepMode_Batch {
		t.Fatalf("Step 3 ReportingMode mismatch")
	}
	if s3.ReportingMode.BatchRepConditions == nil || *s3.ReportingMode.BatchRepConditions.NumInterval != 5 {
		t.Errorf("Step 3 BatchRepConditions NumInterval mismatch")
	}
	if s3.ReportingMode.BatchRepType == nil || !s3.ReportingMode.BatchRepType.ReportPosition || *s3.ReportingMode.BatchRepType.DiscardOldest != true {
		t.Errorf("Step 3 BatchRepType mismatch")
	}
	if s3.GnssPosTechnology == nil || !s3.GnssPosTechnology.Gps || !s3.GnssPosTechnology.Galileo {
		t.Errorf("Step 3 GnssPosTechnology flags mismatch")
	}

	// =========================================================================
	// Step 4: Event Occurs -> SET -> SLP: SUPL POS INIT
	// =========================================================================
	step4PDU := supl1.ULPPDU{
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOSINIT,
			MsSUPLPOSINIT: &supl1.SUPLPOSINIT{
				SETCapabilities: step2PDU.Message.MsSUPLTRIGGEREDSTART.SETCapabilities,
				LocationId: supl1.LocationId{
					Status: supl1.Status_Current,
					CellInfo: supl1.CellInfo{
						Choice: supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{
							RefMCC: 208, RefMNC: 10, RefLAC: 100, RefCI: 205,
						},
					},
				},
				Position: &supl1.Position{
					Timestamp: "260928123000Z",
					PositionEstimate: supl1.PositionEstimate{
						LatitudeSign: supl1.PositionEstimateLatitudeSign_North,
						Latitude:     4885884,
						Longitude:    229435,
						Confidence:   ptr(int64(90)),
					},
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
	if dec4.Message.MsSUPLPOSINIT == nil || dec4.Message.MsSUPLPOSINIT.Position == nil || dec4.Message.MsSUPLPOSINIT.Position.PositionEstimate.Latitude != 4885884 {
		t.Fatalf("Step 4 SUPLPOSINIT field mismatch")
	}

	// =========================================================================
	// Step 5: SLP <-> SET: SUPL POS (RRLP exchange)
	// =========================================================================
	step5PDU := supl1.ULPPDU{
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLPOS,
			MsSUPLPOS: &supl1.SUPLPOS{
				PosPayLoad: supl1.PosPayLoad{
					Choice:      supl1.PosPayLoadChoice_RrlpPayload,
					RrlpPayload: ptr([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
				},
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
	if dec5.Message.MsSUPLPOS == nil || !bytes.Equal(*dec5.Message.MsSUPLPOS.PosPayLoad.RrlpPayload, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("Step 5 SUPLPOS payload mismatch")
	}

	// =========================================================================
	// Step 6: SET -> SLP: SUPL REPORT (Batch report data list with positions)
	// =========================================================================
	step6PDU := supl1.ULPPDU{
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLREPORT,
			MsSUPLREPORT: &supl1.Ver2SUPLREPORT{
				SessionList: &supl1.SessionList{
					{SessionID: supl1.SessionID{SetSessionID: dec2.SessionID.SetSessionID}},
				},
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
							PosMethod: ptr(supl1.PosMethod_AgpsSETassisted),
						},
						ResultCode: ptr(supl1.ResultCode_Noposition),
						Timestamp: &supl1.TimeStamp{
							Choice:       supl1.TimeStampChoice_AbsoluteTime,
							AbsoluteTime: ptr("260928123000Z"),
						},
					},
				},
				Ver:            ptr(supl1.Ver(uper.NewBitString([]byte{0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}, 64))),
				MoreComponents: &uper.Null{},
			},
		},
	}

	raw6, err := supl1.Marshal(&step6PDU)
	if err != nil {
		t.Fatalf("Step 6 Marshal failed: %v", err)
	}
	t.Logf("EVENT_STEP6_REPORT_HEX: %X", raw6)
	var dec6 supl1.ULPPDU
	if err := supl1.Unmarshal(raw6, &dec6); err != nil {
		t.Fatalf("Step 6 Unmarshal failed: %v", err)
	}
	s6 := dec6.Message.MsSUPLREPORT
	if s6 == nil || s6.ReportDataList == nil || len(*s6.ReportDataList) != 1 {
		t.Fatalf("Step 6 ReportDataList mismatch")
	}
	rd := (*s6.ReportDataList)[0]
	if rd.PositionData == nil || rd.PositionData.Position.PositionEstimate.Latitude != 4885884 {
		t.Errorf("Step 6 ReportData PositionData mismatch")
	}
	if rd.ResultCode == nil || *rd.ResultCode != supl1.ResultCode_Noposition {
		t.Errorf("Step 6 ResultCode mismatch")
	}
	if rd.Timestamp == nil || rd.Timestamp.Choice != supl1.TimeStampChoice_AbsoluteTime || *rd.Timestamp.AbsoluteTime != "260928123000Z" {
		t.Errorf("Step 6 TimeStamp AbsoluteTime mismatch")
	}
	if s6.MoreComponents == nil {
		t.Errorf("Step 6 MoreComponents (NULL) mismatch")
	}

	// =========================================================================
	// Step 7: SLP -> SET: SUPL TRIGGERED STOP (Session cancelled / finished)
	// =========================================================================
	step7PDU := supl1.ULPPDU{
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLTRIGGEREDSTOP,
			MsSUPLTRIGGEREDSTOP: &supl1.Ver2SUPLTRIGGEREDSTOP{
				StatusCode: ptr(supl1.StatusCode_Ver2SessionStopped),
			},
		},
	}

	raw7, err := supl1.Marshal(&step7PDU)
	if err != nil {
		t.Fatalf("Step 7 Marshal failed: %v", err)
	}
	t.Logf("EVENT_STEP7_TRIGGEREDSTOP_HEX: %X", raw7)
	var dec7 supl1.ULPPDU
	if err := supl1.Unmarshal(raw7, &dec7); err != nil {
		t.Fatalf("Step 7 Unmarshal failed: %v", err)
	}
	if dec7.Message.MsSUPLTRIGGEREDSTOP == nil || dec7.Message.MsSUPLTRIGGEREDSTOP.StatusCode == nil {
		t.Fatalf("Step 7 MsSUPLTRIGGEREDSTOP or StatusCode is nil")
	}
	if *dec7.Message.MsSUPLTRIGGEREDSTOP.StatusCode != supl1.StatusCode_Ver2SessionStopped {
		t.Errorf("Step 7 StatusCode expected Ver2SessionStopped, got: %v", *dec7.Message.MsSUPLTRIGGEREDSTOP.StatusCode)
	}

	// =========================================================================
	// Step 8: Final session closure: SUPL END
	// =========================================================================
	step8PDU := supl1.ULPPDU{
		Version:   supl1.Version{Maj: 2, Min: 0, Servind: 0},
		SessionID: dec2.SessionID,
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLEND,
			MsSUPLEND: &supl1.SUPLEND{
				StatusCode: ptr(supl1.StatusCode_Unspecified),
			},
		},
	}
	raw8, err := supl1.Marshal(&step8PDU)
	if err != nil {
		t.Fatalf("Step 8 Marshal failed: %v", err)
	}
	var dec8 supl1.ULPPDU
	if err := supl1.Unmarshal(raw8, &dec8); err != nil {
		t.Fatalf("Step 8 Unmarshal failed: %v", err)
	}
	if dec8.Message.MsSUPLEND == nil || *dec8.Message.MsSUPLEND.StatusCode != supl1.StatusCode_Unspecified {
		t.Errorf("Step 8 SUPLEND status mismatch")
	}
}

// TestCallFlow_EventTrigger_MinimalFields tests Event Trigger messages with all optional fields nil.
func TestCallFlow_EventTrigger_MinimalFields(t *testing.T) {
	// Minimal SUPLTRIGGEREDSTART
	startPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
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
						Choice: supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{
							RefMCC: 1, RefMNC: 1, RefLAC: 1, RefCI: 1,
						},
					},
				},
				// Optionals nil: Ver, QoP, MultipleLocationIds, ThirdParty, ApplicationID, TriggerType, TriggerParams, Position, ReportingCap, CauseCode
			},
		},
	}
	rawStart, err := supl1.Marshal(&startPDU)
	if err != nil {
		t.Fatalf("Minimal TRIGGEREDSTART Marshal failed: %v", err)
	}
	var decStart supl1.ULPPDU
	if err := supl1.Unmarshal(rawStart, &decStart); err != nil {
		t.Fatalf("Minimal TRIGGEREDSTART Unmarshal failed: %v", err)
	}
	s := decStart.Message.MsSUPLTRIGGEREDSTART
	if s.Ver != nil || s.QoP != nil || s.MultipleLocationIds != nil || s.ThirdParty != nil || s.ApplicationID != nil || s.TriggerType != nil || s.TriggerParams != nil || s.Position != nil || s.ReportingCap != nil || s.CauseCode != nil {
		t.Errorf("Expected all optional fields to be nil in minimal TRIGGEREDSTART: %+v", s)
	}

	// Minimal SUPLTRIGGEREDRESPONSE
	respPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLTRIGGEREDRESPONSE,
			MsSUPLTRIGGEREDRESPONSE: &supl1.Ver2SUPLTRIGGEREDRESPONSE{
				PosMethod: supl1.PosMethod_AgpsSETassisted,
				// Optionals nil: TriggerParams, SLPAddress, SupportedNetworkInformation, ReportingMode, Keys...
			},
		},
	}
	rawResp, err := supl1.Marshal(&respPDU)
	if err != nil {
		t.Fatalf("Minimal TRIGGEREDRESPONSE Marshal failed: %v", err)
	}
	var decResp supl1.ULPPDU
	if err := supl1.Unmarshal(rawResp, &decResp); err != nil {
		t.Fatalf("Minimal TRIGGEREDRESPONSE Unmarshal failed: %v", err)
	}
	r := decResp.Message.MsSUPLTRIGGEREDRESPONSE
	if r.TriggerParams != nil || r.SLPAddress != nil || r.SupportedNetworkInformation != nil || r.ReportingMode != nil || r.GnssPosTechnology != nil {
		t.Errorf("Expected all optionals to be nil in minimal TRIGGEREDRESPONSE: %+v", r)
	}

	// Minimal SUPLREPORT
	repPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLREPORT,
			MsSUPLREPORT: &supl1.Ver2SUPLREPORT{
				// All optionals nil: SessionList, SETCapabilities, ReportDataList, Ver, MoreComponents
			},
		},
	}
	rawRep, err := supl1.Marshal(&repPDU)
	if err != nil {
		t.Fatalf("Minimal SUPLREPORT Marshal failed: %v", err)
	}
	var decRep supl1.ULPPDU
	if err := supl1.Unmarshal(rawRep, &decRep); err != nil {
		t.Fatalf("Minimal SUPLREPORT Unmarshal failed: %v", err)
	}
	rep := decRep.Message.MsSUPLREPORT
	if rep.SessionList != nil || rep.SETCapabilities != nil || rep.ReportDataList != nil || rep.Ver != nil || rep.MoreComponents != nil {
		t.Errorf("Expected all optionals to be nil in minimal SUPLREPORT: %+v", rep)
	}

	// Minimal SUPLTRIGGEREDSTOP
	stopPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLTRIGGEREDSTOP,
			MsSUPLTRIGGEREDSTOP: &supl1.Ver2SUPLTRIGGEREDSTOP{
				// StatusCode nil
			},
		},
	}
	rawStop, err := supl1.Marshal(&stopPDU)
	if err != nil {
		t.Fatalf("Minimal TRIGGEREDSTOP Marshal failed: %v", err)
	}
	var decStop supl1.ULPPDU
	if err := supl1.Unmarshal(rawStop, &decStop); err != nil {
		t.Fatalf("Minimal TRIGGEREDSTOP Unmarshal failed: %v", err)
	}
	if decStop.Message.MsSUPLTRIGGEREDSTOP.StatusCode != nil {
		t.Errorf("Expected StatusCode to be nil in minimal TRIGGEREDSTOP")
	}
}

// TestCallFlow_EventTrigger_ChoiceVariants verifies choice variants: PeriodicParams vs AreaEventParams,
// and TimeStamp RelativeTime vs AbsoluteTime.
func TestCallFlow_EventTrigger_ChoiceVariants(t *testing.T) {
	// 1. PeriodicParams in TriggerParams
	perPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
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
						Choice: supl1.CellInfoChoice_GsmCell,
						GsmCell: &supl1.GsmCellInformation{
							RefMCC: 1, RefMNC: 1, RefLAC: 1, RefCI: 1,
						},
					},
				},
				TriggerType: ptr(supl1.TriggerType_Periodic),
				TriggerParams: &supl1.TriggerParams{
					Choice: supl1.TriggerParamsChoice_PeriodicParams,
					PeriodicParams: &supl1.PeriodicParams{
						NumberOfFixes:        100,
						IntervalBetweenFixes: 30,
						StartTime:            ptr(int64(0)),
					},
				},
			},
		},
	}
	rawPer, err := supl1.Marshal(&perPDU)
	if err != nil {
		t.Fatalf("PeriodicParams Marshal failed: %v", err)
	}
	var decPer supl1.ULPPDU
	if err := supl1.Unmarshal(rawPer, &decPer); err != nil {
		t.Fatalf("PeriodicParams Unmarshal failed: %v", err)
	}
	s := decPer.Message.MsSUPLTRIGGEREDSTART
	if s.TriggerParams.Choice != supl1.TriggerParamsChoice_PeriodicParams {
		t.Errorf("Expected PeriodicParams choice")
	}
	if s.TriggerParams.PeriodicParams.NumberOfFixes != 100 || s.TriggerParams.PeriodicParams.IntervalBetweenFixes != 30 {
		t.Errorf("PeriodicParams values mismatch")
	}

	// 2. RelativeTime in TimeStamp
	relPDU := supl1.ULPPDU{
		Version: supl1.Version{Maj: 2, Min: 0, Servind: 0},
		Message: supl1.UlpMessage{
			Choice: supl1.UlpMessageChoice_MsSUPLREPORT,
			MsSUPLREPORT: &supl1.Ver2SUPLREPORT{
				ReportDataList: &supl1.ReportDataList{
					{
						Timestamp: &supl1.TimeStamp{
							Choice:       supl1.TimeStampChoice_RelativeTime,
							RelativeTime: ptr(int64(120)), // 120 seconds ago
						},
					},
				},
			},
		},
	}
	rawRel, err := supl1.Marshal(&relPDU)
	if err != nil {
		t.Fatalf("RelativeTime Marshal failed: %v", err)
	}
	var decRel supl1.ULPPDU
	if err := supl1.Unmarshal(rawRel, &decRel); err != nil {
		t.Fatalf("RelativeTime Unmarshal failed: %v", err)
	}
	rd := (*decRel.Message.MsSUPLREPORT.ReportDataList)[0]
	if rd.Timestamp.Choice != supl1.TimeStampChoice_RelativeTime || *rd.Timestamp.RelativeTime != 120 {
		t.Errorf("RelativeTime mismatch: %+v", rd.Timestamp)
	}
}
