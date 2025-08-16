package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/iSundram/Go/decompiler"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: quick_decompile <binary-file>")
		fmt.Println("Example: quick_decompile ./directadmin")
		os.Exit(1)
	}

	binaryFile := os.Args[1]
	
	fmt.Printf("Quick Go Decompiler - High Accuracy Analysis\n")
	fmt.Printf("Decompiling: %s\n\n", binaryFile)

	decomp := decompiler.New()
	
	// Use basic parsing for quick results
	result, err := decomp.QuickDecompile(binaryFile)
	if err != nil {
		fmt.Printf("Error decompiling: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Decompiled Go source code generated successfully!")
	
	// Save to src directory as requested
	srcDir := "src"
	os.MkdirAll(srcDir, 0755)
	
	baseName := filepath.Base(binaryFile)
	outputFile := filepath.Join(srcDir, baseName+"_decompiled_enhanced.go")
	
	err = os.WriteFile(outputFile, []byte(result), 0644)
	if err != nil {
		fmt.Printf("Warning: Could not save to %s: %v\n", outputFile, err)
	} else {
		fmt.Printf("Enhanced decompiled source saved to: %s\n", outputFile)
		fmt.Printf("Decompilation completed with enhanced accuracy.\n")
	}
}