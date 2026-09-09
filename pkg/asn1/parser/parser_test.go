package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSuplFiles(t *testing.T) {
	files := []string{
		"../../../example/supl1/ULP.asn",
		"../../../example/supl1/SUPL.asn",
		"../../../example/supl1/ULP-Components.asn",
	}

	totalModules := 0
	totalTypes := 0
	totalConstants := 0

	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err != nil {
			t.Fatalf("abs path %s failed: %v", file, err)
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			t.Fatalf("reading %s failed: %v", absPath, err)
		}

		astFile, err := ParseFileFromSource(absPath, string(data))
		if err != nil {
			t.Fatalf("parsing %s failed: %v", file, err)
		}

		totalModules += len(astFile.Modules)
		for _, mod := range astFile.Modules {
			totalTypes += len(mod.TypeAssignments)
			totalConstants += len(mod.ValueAssignments)
			t.Logf("Module %s: %d types, %d constants", mod.Name, len(mod.TypeAssignments), len(mod.ValueAssignments))
		}
	}

	if totalModules != 20 {
		t.Fatalf("expected 20 modules across supl1 files, got %d", totalModules)
	}

	t.Logf("Successfully parsed all files: %d modules, %d types, %d constants", totalModules, totalTypes, totalConstants)
}
