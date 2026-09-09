package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"ans2go/pkg/asn1/ast"
	"ans2go/pkg/asn1/parser"
)

func TestAnalyzeSuplFiles(t *testing.T) {
	files := []string{
		"../../../example/supl1/ULP.asn",
		"../../../example/supl1/SUPL.asn",
		"../../../example/supl1/ULP-Components.asn",
	}

	var parsedFiles []*ast.File
	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err != nil {
			t.Fatalf("abs path %s: %v", file, err)
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			t.Fatalf("reading %s: %v", absPath, err)
		}
		astFile, err := parser.ParseFileFromSource(absPath, string(data))
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}
		parsedFiles = append(parsedFiles, astFile)
	}

	model, err := Analyze(parsedFiles)
	if err != nil {
		t.Fatalf("analyzer failed: %v", err)
	}

	t.Logf("Analysis successful: %d constants resolved, %d total top-level types (including lifted anonymous types)", len(model.Constants), len(model.Types))

	// Verify constant resolution
	if model.Constants["maxReqLength"] != 50 {
		t.Fatalf("expected maxReqLength == 50, got %d", model.Constants["maxReqLength"])
	}
	if model.Constants["maxNumGeoArea"] != 32 {
		t.Fatalf("expected maxNumGeoArea == 32, got %d", model.Constants["maxNumGeoArea"])
	}

	// Verify that anonymous types were lifted
	if _, ok := model.Types["PositionEstimate_uncertainty"]; !ok {
		t.Fatalf("expected lifted type PositionEstimate_uncertainty")
	}
	if _, ok := model.Types["CellMeasuredResults_modeSpecificInfo"]; !ok {
		t.Fatalf("expected lifted type CellMeasuredResults_modeSpecificInfo")
	}
}
