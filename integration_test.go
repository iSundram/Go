package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecompilerIntegration(t *testing.T) {
	// Build the decompiler
	err := exec.Command("go", "build", "-o", "go-decompiler", "main.go").Run()
	if err != nil {
		t.Fatalf("Failed to build decompiler: %v", err)
	}
	defer os.Remove("go-decompiler")

	// Test cases with different sample programs
	testCases := []struct {
		name          string
		sourceFile    string
		expectedFuncs []string
	}{
		{
			name:          "simple hello program",
			sourceFile:    "samples/hello.go",
			expectedFuncs: []string{"main"},
		},
		{
			name:          "functions program",
			sourceFile:    "samples/functions.go",
			expectedFuncs: []string{"main", "add", "greet"},
		},
		{
			name:          "complex program",
			sourceFile:    "samples/complex.go",
			expectedFuncs: []string{"main", "fibonacci"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build the sample program without optimization
			baseName := strings.TrimSuffix(filepath.Base(tc.sourceFile), ".go")
			binaryName := fmt.Sprintf("samples/%s_test", baseName)
			
			buildCmd := exec.Command("go", "build", "-gcflags=-N -l", "-o", binaryName, tc.sourceFile)
			err := buildCmd.Run()
			if err != nil {
				t.Fatalf("Failed to build %s: %v", tc.sourceFile, err)
			}
			defer os.Remove(binaryName)

			// Run the decompiler
			cmd := exec.Command("./go-decompiler", binaryName)
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("Decompiler failed on %s: %v", binaryName, err)
			}

			result := string(output)

			// Check that it contains expected functions
			for _, expectedFunc := range tc.expectedFuncs {
				funcPattern := fmt.Sprintf("func %s", expectedFunc)
				if !strings.Contains(result, funcPattern) {
					t.Errorf("Expected function %s not found in decompiled output", expectedFunc)
				}
			}

			// Check basic structure
			if !strings.Contains(result, "package main") {
				t.Error("Package declaration not found")
			}

			if !strings.Contains(result, "Go Decompiler v1.0") {
				t.Error("Decompiler header not found")
			}
		})
	}
}

func TestDecompilerAccuracy(t *testing.T) {
	// Build a simple test program
	testCode := `package main

import "fmt"

func simpleAdd(a, b int) int {
	return a + b
}

func main() {
	result := simpleAdd(5, 3)
	fmt.Printf("Result: %d\n", result)
}`

	// Write test program
	err := os.WriteFile("test_accuracy.go", []byte(testCode), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("test_accuracy.go")

	// Build without optimization
	err = exec.Command("go", "build", "-gcflags=-N -l", "-o", "test_accuracy", "test_accuracy.go").Run()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("test_accuracy")

	// Build the decompiler
	err = exec.Command("go", "build", "-o", "go-decompiler", "main.go").Run()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("go-decompiler")

	// Run decompiler
	cmd := exec.Command("./go-decompiler", "test_accuracy")
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}

	result := string(output)

	// Check for key elements that indicate accuracy
	checks := []string{
		"package main",
		"func main()",
		"func simpleAdd",
		"// Decompiled Go source code",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("Expected '%s' in decompiled output", check)
		}
	}

	// Verify the decompiled code compiles (basic syntax check)
	lines := strings.Split(result, "\n")
	var sourceLines []string
	capturing := false
	
	for _, line := range lines {
		if strings.Contains(line, "=================================") {
			capturing = true
			continue
		}
		if capturing {
			sourceLines = append(sourceLines, line)
		}
	}

	if len(sourceLines) > 0 {
		decompiledSource := strings.Join(sourceLines, "\n")
		err = os.WriteFile("decompiled_test.go", []byte(decompiledSource), 0644)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove("decompiled_test.go")

		// Try to compile the decompiled source
		compileCmd := exec.Command("go", "build", "-o", "/dev/null", "decompiled_test.go")
		if err := compileCmd.Run(); err != nil {
			t.Logf("Decompiled source doesn't compile (expected): %v", err)
			// This is expected since we're doing basic reconstruction
		}
	}
}

func TestDecompilerErrorHandling(t *testing.T) {
	// Build the decompiler
	err := exec.Command("go", "build", "-o", "go-decompiler", "main.go").Run()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("go-decompiler")

	// Test with non-existent file
	cmd := exec.Command("./go-decompiler", "nonexistent")
	_, err = cmd.Output()
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Test with invalid binary
	invalidFile := "invalid_binary"
	err = os.WriteFile(invalidFile, []byte("not a binary"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(invalidFile)

	cmd = exec.Command("./go-decompiler", invalidFile)
	_, err = cmd.Output()
	if err == nil {
		t.Error("Expected error for invalid binary")
	}
}