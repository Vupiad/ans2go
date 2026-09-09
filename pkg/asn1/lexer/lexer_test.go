package lexer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLexerSuplFiles(t *testing.T) {
	files := []string{
		"../../../example/supl1/ULP.asn",
		"../../../example/supl1/SUPL.asn",
		"../../../example/supl1/ULP-Components.asn",
	}

	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err != nil {
			t.Fatalf("abs path %s failed: %v", file, err)
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			t.Fatalf("reading %s failed: %v", absPath, err)
		}

		tokens, err := TokenizeAll(string(data))
		if err != nil {
			t.Fatalf("tokenizing %s failed: %v", file, err)
		}
		if len(tokens) == 0 {
			t.Fatalf("file %s produced 0 tokens", file)
		}
		t.Logf("File %s tokenized successfully: %d tokens", filepath.Base(file), len(tokens))
	}
}
