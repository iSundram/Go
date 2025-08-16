package main

import (
	"fmt"
	"os"

	"github.com/iSundram/Go/decompiler"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go-decompiler <binary-file>")
		fmt.Println("Example: go-decompiler ./sample_program")
		os.Exit(1)
	}

	binaryFile := os.Args[1]
	
	fmt.Printf("Go Decompiler v1.0\n")
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
}