package decompiler

import (
	"os"
	"strings"
	"testing"
)

func TestDecompilerNew(t *testing.T) {
	decomp := New()
	if decomp == nil {
		t.Fatal("New() returned nil")
	}
	
	if len(decomp.symbols) != 0 {
		t.Errorf("Expected empty symbols, got %d", len(decomp.symbols))
	}
	
	if len(decomp.functions) != 0 {
		t.Errorf("Expected empty functions, got %d", len(decomp.functions))
	}
}

func TestDetectFormat(t *testing.T) {
	// Create a temporary ELF-like file for testing
	tmpFile, err := os.CreateTemp("", "test_elf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	
	// Write ELF magic bytes
	elfMagic := []byte{0x7F, 'E', 'L', 'F'}
	tmpFile.Write(elfMagic)
	tmpFile.Close()
	
	decomp := New()
	file, err := os.Open(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	
	format, err := decomp.detectFormat(file)
	if err != nil {
		t.Fatalf("detectFormat failed: %v", err)
	}
	
	if format != "ELF" {
		t.Errorf("Expected ELF format, got %s", format)
	}
}

func TestIsValidGoIdentifier(t *testing.T) {
	decomp := New()
	
	testCases := []struct {
		input    string
		expected bool
	}{
		{"main", true},
		{"add", true},
		{"greet", true},
		{"MyFunction", true},
		{"_private", true},
		{"", false},
		{"123invalid", false},
		{"hello-world", false},
		{"hello.world", false},
		{"hello world", false},
	}
	
	for _, tc := range testCases {
		result := decomp.isValidGoIdentifier(tc.input)
		if result != tc.expected {
			t.Errorf("isValidGoIdentifier(%q) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestIsSystemString(t *testing.T) {
	decomp := New()
	
	testCases := []struct {
		input    string
		expected bool
	}{
		{"Hello, World!", false},
		{"runtime.GC", true},
		{"GODEBUG", true},
		{"libc.so.6", true},
		{"goroutine", true},
		{"user message", false},
		{"123456", true}, // mostly numbers
		{"!!!@@@", true}, // mostly special chars
	}
	
	for _, tc := range testCases {
		result := decomp.isSystemString(tc.input)
		if result != tc.expected {
			t.Errorf("isSystemString(%q) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestIsUserDefinedFunction(t *testing.T) {
	decomp := New()
	
	testCases := []struct {
		input    string
		expected bool
	}{
		{"main.main", true},
		{"main.add", true},
		{"main.greet", true},
		{"mypackage.MyFunction", true},
		{"runtime.GC", false},
		{"type:.eq.someType", false},
		{"go:main.inittasks", false},
		{"fmt.Println", false},
		{"internal/cpu.Initialize", false},
		{"sync/atomic.StorePointer", false},
	}
	
	for _, tc := range testCases {
		result := decomp.isUserDefinedFunction(tc.input)
		if result != tc.expected {
			t.Errorf("isUserDefinedFunction(%q) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestInferParameters(t *testing.T) {
	decomp := New()
	
	testCases := []struct {
		input    string
		expected []string
	}{
		{"main.addString", []string{"s string"}},
		{"main.addInt", []string{"n int"}},
		{"main.normal", []string{}},
	}
	
	for _, tc := range testCases {
		result := decomp.inferParameters(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("inferParameters(%q) returned %d params, expected %d", tc.input, len(result), len(tc.expected))
			continue
		}
		
		for i, param := range result {
			if param != tc.expected[i] {
				t.Errorf("inferParameters(%q)[%d] = %q, expected %q", tc.input, i, param, tc.expected[i])
			}
		}
	}
}

func TestInferReturnType(t *testing.T) {
	decomp := New()
	
	testCases := []struct {
		input    string
		expected string
	}{
		{"main.getString", "string"},
		{"main.getInt", "int"},
		{"main.getBool", "bool"},
		{"main.normal", ""},
	}
	
	for _, tc := range testCases {
		result := decomp.inferReturnType(tc.input)
		if result != tc.expected {
			t.Errorf("inferReturnType(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestGenerateSource(t *testing.T) {
	decomp := New()
	
	// Add some test data
	decomp.functions = []Function{
		{
			Name:       "main",
			Body:       "\tfmt.Println(\"Hello, World!\")\n",
			Parameters: []string{},
			ReturnType: "",
		},
		{
			Name:       "add",
			Body:       "\treturn a + b\n",
			Parameters: []string{"a int", "b int"},
			ReturnType: "int",
		},
	}
	decomp.imports = []string{"fmt"}
	
	source := decomp.generateSource()
	
	// Check that the source contains expected elements
	if !strings.Contains(source, "package main") {
		t.Error("Generated source missing package declaration")
	}
	
	if !strings.Contains(source, "import") {
		t.Error("Generated source missing imports")
	}
	
	if !strings.Contains(source, "func main()") {
		t.Error("Generated source missing main function")
	}
	
	if !strings.Contains(source, "func add(a int, b int) int") {
		t.Error("Generated source missing add function with parameters")
	}
}

func TestEscapeString(t *testing.T) {
	decomp := New()
	
	testCases := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"hello\nworld", "hello\\nworld"},
		{"hello\tworld", "hello\\tworld"},
		{"hello\"world", "hello\\\"world"},
		{"hello\\world", "hello\\\\world"},
	}
	
	for _, tc := range testCases {
		result := decomp.escapeString(tc.input)
		if result != tc.expected {
			t.Errorf("escapeString(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}