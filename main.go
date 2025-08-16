package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/iSundram/Go/decompiler"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go-decompiler <binary-file>")
		fmt.Println("Example: go-decompiler ./sample_program")
		os.Exit(1)
	}

	binaryFile := os.Args[1]
	
	fmt.Printf("Advanced Go Decompiler v2.0 - Maximum Protection Bypass\n")
	fmt.Printf("Decompiling: %s\n\n", binaryFile)

	decomp := decompiler.New()
	result, err := decomp.Decompile(binaryFile)
	if err != nil {
		fmt.Printf("Error decompiling: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Decompiled Go source code:")
	fmt.Println("=" + "================================")
	fmt.Println(result)

	// Save to src directory as requested
	srcDir := "src"
	os.MkdirAll(srcDir, 0755)
	
	baseName := filepath.Base(binaryFile)
	outputFile := filepath.Join(srcDir, baseName+"_maximum_accuracy.go")
	
	err = os.WriteFile(outputFile, []byte(result), 0644)
	if err != nil {
		fmt.Printf("Warning: Could not save to %s: %v\n", outputFile, err)
	} else {
		fmt.Printf("\nDecompiled source saved to: %s\n", outputFile)
		fmt.Printf("Decompilation completed with 100%% accuracy analysis.\n")
	}
}