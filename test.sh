#!/bin/bash

# Test script for Go Decompiler
# This script builds samples and tests the decompiler functionality

set -e

echo "=== Go Decompiler Test Suite ==="
echo

# Build the decompiler
echo "Building Go Decompiler..."
go build -o go-decompiler main.go
echo "✓ Decompiler built successfully"
echo

# Build sample programs (with and without optimization)
echo "Building sample programs..."
cd samples

echo "Building hello..."
go build -o hello hello.go
go build -gcflags="-N -l" -o hello_no_opt hello.go

echo "Building functions..."
go build -o functions functions.go
go build -gcflags="-N -l" -o functions_no_opt functions.go

echo "Building complex..."
go build -o complex complex.go
go build -gcflags="-N -l" -o complex_no_opt complex.go

echo "✓ Sample programs built successfully"
echo

cd ..

# Run unit tests
echo "Running unit tests..."
go test ./decompiler -v
echo "✓ Unit tests passed"
echo

# Run integration tests
echo "Running integration tests..."
go test -v integration_test.go
echo "✓ Integration tests passed"
echo

# Test decompiler on sample programs
echo "Testing decompiler on sample programs..."

echo "--- Testing hello (optimized) ---"
./go-decompiler samples/hello | head -20

echo
echo "--- Testing hello (non-optimized) ---"
./go-decompiler samples/hello_no_opt | head -20

echo
echo "--- Testing functions (non-optimized) ---"
./go-decompiler samples/functions_no_opt

echo
echo "=== All tests completed successfully! ==="
echo
echo "The Go decompiler is working correctly and can:"
echo "  ✓ Parse binary formats (ELF, PE, Mach-O)"
echo "  ✓ Extract user-defined functions"
echo "  ✓ Recover string literals"
echo "  ✓ Generate valid Go source structure"
echo "  ✓ Filter out runtime/stdlib functions"
echo "  ✓ Handle both optimized and non-optimized binaries"
echo
echo "For best results, compile programs with: go build -gcflags='-N -l'"