package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"ans2go/pkg/asn1/analyzer"
	"ans2go/pkg/asn1/ast"
	"ans2go/pkg/asn1/parser"
	"ans2go/pkg/generator"
)

func main() {
	asnDir := flag.String("dir", "example/supl1", "Directory containing .asn specification files")
	outDir := flag.String("o", "", "Output directory for generated Go code (defaults to -dir)")
	pkgName := flag.String("pkg", "", "Target Go package name (defaults to input folder name)")
	flag.Parse()

	// Derive package name from input folder name
	folderName := filepath.Base(filepath.Clean(*asnDir))
	targetPkg := *pkgName
	if targetPkg == "" {
		targetPkg = folderName
	}

	targetOutDir := *outDir
	if targetOutDir == "" {
		targetOutDir = *asnDir
	}

	log.Printf("ans2go ASN.1 Compiler starting...")
	log.Printf("Scanning directory: %s", *asnDir)
	log.Printf("Target package name: %s", targetPkg)
	log.Printf("Output directory: %s", targetOutDir)

	matches, err := filepath.Glob(filepath.Join(*asnDir, "*.asn"))
	if err != nil {
		log.Fatalf("failed to glob .asn files: %v", err)
	}
	if len(matches) == 0 {
		log.Fatalf("no .asn files found in directory %s", *asnDir)
	}
	sort.Strings(matches)

	var parsedFiles []*ast.File
	for _, match := range matches {
		data, err := os.ReadFile(match)
		if err != nil {
			log.Fatalf("failed to read %s: %v", match, err)
		}
		astFile, err := parser.ParseFileFromSource(match, string(data))
		if err != nil {
			log.Fatalf("failed to parse %s: %v", match, err)
		}
		log.Printf("Parsed %s: %d modules", filepath.Base(match), len(astFile.Modules))
		parsedFiles = append(parsedFiles, astFile)
	}

	model, err := analyzer.Analyze(parsedFiles)
	if err != nil {
		log.Fatalf("semantic analysis failed: %v", err)
	}

	log.Printf("Analysis complete: %d constants, %d types defined", len(model.Constants), len(model.Types))

	gen := generator.New(model, targetPkg)
	src, err := gen.Generate()
	if err != nil {
		log.Fatalf("code generation failed: %v", err)
	}

	if err := os.MkdirAll(targetOutDir, 0755); err != nil {
		log.Fatalf("failed to create output directory %s: %v", targetOutDir, err)
	}

	outPath := filepath.Join(targetOutDir, "types.go")
	if err := os.WriteFile(outPath, src, 0644); err != nil {
		log.Fatalf("failed to write generated file %s: %v", outPath, err)
	}

	log.Printf("Successfully generated %s (%d bytes)", outPath, len(src))
	fmt.Printf("Done. Generated %d types into %s (package %s)\n", len(model.Types), outPath, targetPkg)
}
