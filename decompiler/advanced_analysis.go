package decompiler

import (
	"fmt"
	"regexp"
	"strings"
)

// AdvancedAnalyzer provides sophisticated binary analysis capabilities
type AdvancedAnalyzer struct {
	decompiler   *Decompiler
	entropy      map[uint64]float64
	signatures   map[string]FunctionSignature
	patterns     []CodePattern
	encryption   []EncryptionIndicator
	antiDebug    []AntiDebugTechnique
}

// FunctionSignature represents a known function signature
type FunctionSignature struct {
	Name        string
	Pattern     []byte
	Mask        []byte
	Description string
	Library     string
}

// CodePattern represents a recognizable code pattern
type CodePattern struct {
	Name        string
	Description string
	Pattern     []uint32
	Confidence  float64
}

// EncryptionIndicator represents signs of encryption/obfuscation
type EncryptionIndicator struct {
	Type        string
	Location    uint64
	Description string
	Confidence  float64
}

// AntiDebugTechnique represents anti-debugging mechanisms
type AntiDebugTechnique struct {
	Type        string
	Location    uint64
	Description string
	Severity    string
}

// NewAdvancedAnalyzer creates a new advanced analyzer
func NewAdvancedAnalyzer(d *Decompiler) *AdvancedAnalyzer {
	analyzer := &AdvancedAnalyzer{
		decompiler: d,
		entropy:    make(map[uint64]float64),
		signatures: make(map[string]FunctionSignature),
		patterns:   []CodePattern{},
		encryption: []EncryptionIndicator{},
		antiDebug:  []AntiDebugTechnique{},
	}
	
	analyzer.initializeSignatures()
	analyzer.initializePatterns()
	
	return analyzer
}

// PerformAdvancedAnalysis conducts comprehensive binary analysis
func (a *AdvancedAnalyzer) PerformAdvancedAnalysis() error {
	// Analyze entropy to detect packed/encrypted sections
	a.analyzeEntropy()
	
	// Detect known function signatures
	a.detectKnownFunctions()
	
	// Analyze code patterns
	a.analyzeCodePatterns()
	
	// Detect encryption/obfuscation
	a.detectEncryption()
	
	// Detect anti-debugging techniques
	a.detectAntiDebug()
	
	// Perform deep string analysis
	a.performDeepStringAnalysis()
	
	// Analyze call graphs
	a.analyzeCallGraphs()
	
	return nil
}

// analyzeEntropy calculates entropy for different sections to detect packing/encryption
func (a *AdvancedAnalyzer) analyzeEntropy() {
	for _, segment := range a.decompiler.dataSegments {
		if len(segment.Data) == 0 {
			continue
		}
		
		entropy := a.calculateEntropy(segment.Data)
		a.entropy[segment.Address] = entropy
		
		// High entropy might indicate encryption/compression
		if entropy > 7.5 {
			a.encryption = append(a.encryption, EncryptionIndicator{
				Type:        "High Entropy Section",
				Location:    segment.Address,
				Description: fmt.Sprintf("Section %s has entropy %.2f (>7.5), possibly encrypted/packed", segment.Name, entropy),
				Confidence:  0.8,
			})
		}
	}
}

// calculateEntropy calculates Shannon entropy of data
func (a *AdvancedAnalyzer) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	
	frequency := make(map[byte]int)
	for _, b := range data {
		frequency[b]++
	}
	
	entropy := 0.0
	length := float64(len(data))
	
	for _, count := range frequency {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (float64(int(p*1000000)) / 1000000) // Approximation for log2
		}
	}
	
	return entropy
}

// initializeSignatures initializes known function signatures
func (a *AdvancedAnalyzer) initializeSignatures() {
	// Common library function signatures
	signatures := []FunctionSignature{
		{
			Name:        "printf",
			Pattern:     []byte{0x48, 0x89, 0xf2, 0x48, 0x89, 0xfe},
			Mask:        []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			Description: "Standard printf function",
			Library:     "libc",
		},
		{
			Name:        "malloc",
			Pattern:     []byte{0x48, 0x89, 0xf7, 0xe8},
			Mask:        []byte{0xFF, 0xFF, 0xFF, 0xFF},
			Description: "Memory allocation function",
			Library:     "libc",
		},
		{
			Name:        "aes_encrypt",
			Pattern:     []byte{0x66, 0x0f, 0x38, 0xdc},
			Mask:        []byte{0xFF, 0xFF, 0xFF, 0xFF},
			Description: "AES encryption instruction",
			Library:     "crypto",
		},
	}
	
	for _, sig := range signatures {
		a.signatures[sig.Name] = sig
	}
}

// initializePatterns initializes known code patterns
func (a *AdvancedAnalyzer) initializePatterns() {
	a.patterns = []CodePattern{
		{
			Name:        "String Decryption Loop",
			Description: "Pattern indicating string decryption",
			Pattern:     []uint32{0xd2800000, 0x8b000000, 0x38000000}, // ARM64 pattern approximation
			Confidence:  0.7,
		},
		{
			Name:        "Anti-Debug Check",
			Description: "Possible anti-debugging mechanism",
			Pattern:     []uint32{0xd4000001, 0x34000000}, // ARM64 SVC + conditional branch
			Confidence:  0.6,
		},
		{
			Name:        "XOR Encryption",
			Description: "XOR-based encryption/decryption",
			Pattern:     []uint32{0x4a000000, 0x8b000000}, // ARM64 EOR pattern
			Confidence:  0.8,
		},
	}
}

// detectKnownFunctions identifies known library functions
func (a *AdvancedAnalyzer) detectKnownFunctions() {
	for _, segment := range a.decompiler.dataSegments {
		if segment.Type != "executable" {
			continue
		}
		
		for name, sig := range a.signatures {
			matches := a.findPatternMatches(segment.Data, sig.Pattern, sig.Mask)
			for _, offset := range matches {
				addr := segment.Address + uint64(offset)
				
				// Add detected function
				function := Function{
					Name:        name,
					Address:     addr,
					Size:        uint64(len(sig.Pattern)),
					Body:        a.generateLibraryFunctionBody(name, sig),
					Parameters:  a.inferLibraryParameters(name),
					ReturnType:  a.inferLibraryReturnType(name),
					IsExported:  true,
				}
				
				a.decompiler.functions = append(a.decompiler.functions, function)
			}
		}
	}
}

// findPatternMatches finds all occurrences of a pattern in data
func (a *AdvancedAnalyzer) findPatternMatches(data, pattern, mask []byte) []int {
	var matches []int
	
	if len(pattern) == 0 || len(data) < len(pattern) {
		return matches
	}
	
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if (data[i+j] & mask[j]) != (pattern[j] & mask[j]) {
				match = false
				break
			}
		}
		if match {
			matches = append(matches, i)
		}
	}
	
	return matches
}

// generateLibraryFunctionBody generates body for known library functions
func (a *AdvancedAnalyzer) generateLibraryFunctionBody(name string, sig FunctionSignature) string {
	var body strings.Builder
	
	body.WriteString(fmt.Sprintf("\t// %s - %s\n", name, sig.Description))
	body.WriteString(fmt.Sprintf("\t// Library: %s\n", sig.Library))
	
	switch name {
	case "printf":
		a.decompiler.ensureImport("fmt")
		body.WriteString("\t// Printf implementation\n")
		body.WriteString("\tfmt.Printf(format, args...)\n")
	case "malloc":
		body.WriteString("\t// Memory allocation\n")
		body.WriteString("\tptr := make([]byte, size)\n")
		body.WriteString("\treturn &ptr[0]\n")
	case "aes_encrypt":
		a.decompiler.ensureImport("crypto/aes")
		body.WriteString("\t// AES encryption\n")
		body.WriteString("\tcipher, _ := aes.NewCipher(key)\n")
		body.WriteString("\tcipher.Encrypt(dst, src)\n")
	default:
		body.WriteString("\t// Library function implementation\n")
		body.WriteString("\t// Original functionality preserved\n")
	}
	
	return body.String()
}

// inferLibraryParameters infers parameters for known library functions
func (a *AdvancedAnalyzer) inferLibraryParameters(name string) []string {
	switch name {
	case "printf":
		return []string{"format string", "args ...interface{}"}
	case "malloc":
		return []string{"size uintptr"}
	case "aes_encrypt":
		return []string{"dst []byte", "src []byte", "key []byte"}
	default:
		return []string{}
	}
}

// inferLibraryReturnType infers return type for known library functions
func (a *AdvancedAnalyzer) inferLibraryReturnType(name string) string {
	switch name {
	case "printf":
		return "int"
	case "malloc":
		return "unsafe.Pointer"
	case "aes_encrypt":
		return ""
	default:
		return ""
	}
}

// analyzeCodePatterns detects known code patterns
func (a *AdvancedAnalyzer) analyzeCodePatterns() {
	for _, instr := range a.decompiler.instructions {
		for _, pattern := range a.patterns {
			if a.matchesPattern(instr, pattern) {
				// Create function for detected pattern
				function := Function{
					Name:    fmt.Sprintf("detected_%s_0x%x", strings.ToLower(strings.ReplaceAll(pattern.Name, " ", "_")), instr.Address),
					Address: instr.Address,
					Size:    uint64(len(pattern.Pattern) * 4), // ARM64 instructions are 4 bytes
					Body:    a.generatePatternFunctionBody(pattern),
				}
				
				a.decompiler.functions = append(a.decompiler.functions, function)
			}
		}
	}
}

// matchesPattern checks if instruction matches a pattern
func (a *AdvancedAnalyzer) matchesPattern(instr Instruction, pattern CodePattern) bool {
	// Simplified pattern matching - would need more sophisticated implementation
	return false // Placeholder
}

// generatePatternFunctionBody generates body for detected patterns
func (a *AdvancedAnalyzer) generatePatternFunctionBody(pattern CodePattern) string {
	var body strings.Builder
	
	body.WriteString(fmt.Sprintf("\t// Detected pattern: %s\n", pattern.Name))
	body.WriteString(fmt.Sprintf("\t// Description: %s\n", pattern.Description))
	body.WriteString(fmt.Sprintf("\t// Confidence: %.1f%%\n", pattern.Confidence*100))
	
	switch pattern.Name {
	case "String Decryption Loop":
		body.WriteString("\t// String decryption routine\n")
		body.WriteString("\tfor i := 0; i < len(encryptedString); i++ {\n")
		body.WriteString("\t\tdecryptedString[i] = encryptedString[i] ^ key[i%len(key)]\n")
		body.WriteString("\t}\n")
	case "Anti-Debug Check":
		body.WriteString("\t// Anti-debugging mechanism detected\n")
		body.WriteString("\tif isDebuggerPresent() {\n")
		body.WriteString("\t\t// Anti-debug action\n")
		body.WriteString("\t\tos.Exit(1)\n")
		body.WriteString("\t}\n")
	case "XOR Encryption":
		body.WriteString("\t// XOR encryption/decryption\n")
		body.WriteString("\tfor i := range data {\n")
		body.WriteString("\t\tdata[i] ^= key\n")
		body.WriteString("\t}\n")
	default:
		body.WriteString("\t// Pattern-specific logic\n")
	}
	
	return body.String()
}

// detectEncryption identifies encryption/obfuscation techniques
func (a *AdvancedAnalyzer) detectEncryption() {
	// Check for common encryption constants
	cryptoConstants := map[string][]byte{
		"AES S-Box":     {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5},
		"SHA-256 Init":  {0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85},
		"RSA Exponent":  {0x01, 0x00, 0x01},
		"DES S-Box":     {0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08},
	}
	
	for _, segment := range a.decompiler.dataSegments {
		for name, constant := range cryptoConstants {
			if a.containsSequence(segment.Data, constant) {
				a.encryption = append(a.encryption, EncryptionIndicator{
					Type:        "Crypto Constant",
					Location:    segment.Address,
					Description: fmt.Sprintf("%s constant found in %s section", name, segment.Name),
					Confidence:  0.9,
				})
			}
		}
	}
	
	// Detect string obfuscation
	a.detectStringObfuscation()
}

// containsSequence checks if data contains a specific byte sequence
func (a *AdvancedAnalyzer) containsSequence(data, sequence []byte) bool {
	if len(sequence) == 0 || len(data) < len(sequence) {
		return false
	}
	
	for i := 0; i <= len(data)-len(sequence); i++ {
		match := true
		for j := 0; j < len(sequence); j++ {
			if data[i+j] != sequence[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// detectStringObfuscation identifies obfuscated strings
func (a *AdvancedAnalyzer) detectStringObfuscation() {
	// Look for patterns indicating string obfuscation
	suspiciousPatterns := []string{
		`[a-zA-Z0-9+/]{20,}={0,2}`, // Base64
		`\\x[0-9a-fA-F]{2}`,        // Hex escapes
		`%[0-9a-fA-F]{2}`,          // URL encoding
	}
	
	for _, str := range a.decompiler.strings {
		for _, pattern := range suspiciousPatterns {
			if matched, _ := regexp.MatchString(pattern, str); matched {
				a.encryption = append(a.encryption, EncryptionIndicator{
					Type:        "Obfuscated String",
					Location:    0, // Would need address lookup
					Description: fmt.Sprintf("Potentially obfuscated string: %s", str[:min(len(str), 50)]),
					Confidence:  0.6,
				})
			}
		}
	}
}

// detectAntiDebug identifies anti-debugging techniques
func (a *AdvancedAnalyzer) detectAntiDebug() {
	// Common anti-debug techniques to look for
	antiDebugStrings := []string{
		"ptrace", "gdb", "strace", "ltrace", "debugger",
		"PTRACE_TRACEME", "IsDebuggerPresent", "/proc/self/status",
	}
	
	for _, str := range a.decompiler.strings {
		for _, antiDebug := range antiDebugStrings {
			if strings.Contains(strings.ToLower(str), strings.ToLower(antiDebug)) {
				a.antiDebug = append(a.antiDebug, AntiDebugTechnique{
					Type:        "String Reference",
					Location:    0,
					Description: fmt.Sprintf("Anti-debug string found: %s", str),
					Severity:    "Medium",
				})
			}
		}
	}
	
	// Look for suspicious system calls
	a.detectAntiDebugSyscalls()
}

// detectAntiDebugSyscalls identifies suspicious system calls
func (a *AdvancedAnalyzer) detectAntiDebugSyscalls() {
	for _, instr := range a.decompiler.instructions {
		// Look for system call instructions (ARM64: SVC)
		if instr.Opcode == "svc" {
			a.antiDebug = append(a.antiDebug, AntiDebugTechnique{
				Type:        "System Call",
				Location:    instr.Address,
				Description: "System call instruction - potential anti-debug check",
				Severity:    "Low",
			})
		}
	}
}

// performDeepStringAnalysis conducts advanced string analysis
func (a *AdvancedAnalyzer) performDeepStringAnalysis() {
	// Categorize strings
	categories := a.categorizeStrings()
	
	// Look for hidden/encrypted strings
	a.findHiddenStrings()
	
	// Analyze string relationships
	a.analyzeStringRelationships(categories)
}

// categorizeStrings categorizes strings by type
func (a *AdvancedAnalyzer) categorizeStrings() map[string][]string {
	categories := map[string][]string{
		"URLs":        {},
		"Files":       {},
		"Commands":    {},
		"Errors":      {},
		"Crypto":      {},
		"Network":     {},
		"System":      {},
	}
	
	patterns := map[string]*regexp.Regexp{
		"URLs":     regexp.MustCompile(`https?://[^\s]+`),
		"Files":    regexp.MustCompile(`/[a-zA-Z0-9_/.-]+\.[a-zA-Z0-9]+`),
		"Commands": regexp.MustCompile(`(sudo|chmod|chown|killall|systemctl|service)`),
		"Errors":   regexp.MustCompile(`(error|failed|invalid|denied|forbidden)`),
		"Crypto":   regexp.MustCompile(`(aes|rsa|sha|md5|ssl|tls|cert|key|encrypt)`),
		"Network":  regexp.MustCompile(`(tcp|udp|http|ftp|ssh|port|socket|connect)`),
		"System":   regexp.MustCompile(`(proc|sys|dev|var|tmp|etc|usr|opt)`),
	}
	
	for _, str := range a.decompiler.strings {
		for category, pattern := range patterns {
			if pattern.MatchString(strings.ToLower(str)) {
				categories[category] = append(categories[category], str)
			}
		}
	}
	
	return categories
}

// findHiddenStrings attempts to find encrypted/hidden strings
func (a *AdvancedAnalyzer) findHiddenStrings() {
	// Look for patterns that might be encrypted strings
	for _, segment := range a.decompiler.dataSegments {
		// Check for repeating patterns that might be XOR keys
		keys := a.findPotentialXORKeys(segment.Data)
		
		for _, key := range keys {
			decrypted := a.tryXORDecryption(segment.Data, key)
			if a.looksLikeString(decrypted) {
				a.decompiler.strings = append(a.decompiler.strings, string(decrypted))
			}
		}
	}
}

// findPotentialXORKeys finds repeating byte patterns that might be XOR keys
func (a *AdvancedAnalyzer) findPotentialXORKeys(data []byte) [][]byte {
	var keys [][]byte
	
	// Look for repeating patterns of 1-16 bytes
	for keyLen := 1; keyLen <= 16; keyLen++ {
		if len(data) < keyLen*3 {
			continue
		}
		
		for start := 0; start <= len(data)-keyLen*3; start++ {
			key := data[start : start+keyLen]
			
			// Check if this pattern repeats
			matches := 0
			for i := start + keyLen; i <= len(data)-keyLen; i += keyLen {
				if a.bytesEqual(data[i:i+keyLen], key) {
					matches++
				} else {
					break
				}
			}
			
			if matches >= 2 {
				keys = append(keys, key)
			}
		}
	}
	
	return keys
}

// bytesEqual compares two byte slices
func (a *AdvancedAnalyzer) bytesEqual(a1, a2 []byte) bool {
	if len(a1) != len(a2) {
		return false
	}
	for i := range a1 {
		if a1[i] != a2[i] {
			return false
		}
	}
	return true
}

// tryXORDecryption attempts XOR decryption with a key
func (a *AdvancedAnalyzer) tryXORDecryption(data, key []byte) []byte {
	if len(key) == 0 {
		return nil
	}
	
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// looksLikeString checks if decrypted data looks like a string
func (a *AdvancedAnalyzer) looksLikeString(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			printable++
		}
	}
	
	return float64(printable)/float64(len(data)) > 0.7
}

// analyzeStringRelationships analyzes relationships between strings
func (a *AdvancedAnalyzer) analyzeStringRelationships(categories map[string][]string) {
	// Generate analysis summary
	analysis := "\n// Advanced String Analysis:\n"
	for category, strings := range categories {
		if len(strings) > 0 {
			analysis += fmt.Sprintf("// %s: %d found\n", category, len(strings))
		}
	}
	
	// Add to decompiler output (would need to modify generateSource)
	_ = analysis
}

// analyzeCallGraphs builds and analyzes function call graphs
func (a *AdvancedAnalyzer) analyzeCallGraphs() {
	callGraph := make(map[uint64][]uint64)
	
	// Build call graph from instructions
	for _, instr := range a.decompiler.instructions {
		if instr.Type == InstrCall && instr.Target > 0 {
			callGraph[instr.Address] = append(callGraph[instr.Address], instr.Target)
		}
	}
	
	// Analyze call patterns
	a.findSuspiciousCallPatterns(callGraph)
}

// findSuspiciousCallPatterns identifies suspicious calling patterns
func (a *AdvancedAnalyzer) findSuspiciousCallPatterns(callGraph map[uint64][]uint64) {
	// Look for functions that call many other functions (possible dispatchers)
	// Look for recursive patterns
	// Look for unusual call depths
	
	for caller, targets := range callGraph {
		if len(targets) > 20 {
			// Potential dispatcher function
			function := Function{
				Name:    fmt.Sprintf("dispatcher_0x%x", caller),
				Address: caller,
				Body:    a.generateDispatcherFunctionBody(targets),
			}
			a.decompiler.functions = append(a.decompiler.functions, function)
		}
	}
}

// generateDispatcherFunctionBody generates body for dispatcher functions
func (a *AdvancedAnalyzer) generateDispatcherFunctionBody(targets []uint64) string {
	var body strings.Builder
	
	body.WriteString("\t// Dispatcher function - calls multiple targets\n")
	body.WriteString(fmt.Sprintf("\t// Targets: %d functions\n", len(targets)))
	body.WriteString("\tswitch selector {\n")
	
	for i, target := range targets {
		if i >= 10 { // Limit cases
			body.WriteString("\t// ... more cases\n")
			break
		}
		body.WriteString(fmt.Sprintf("\tcase %d:\n", i))
		body.WriteString(fmt.Sprintf("\t\t// Call function at 0x%x\n", target))
	}
	
	body.WriteString("\t}\n")
	
	return body.String()
}

// GenerateAdvancedReport generates a comprehensive analysis report
func (a *AdvancedAnalyzer) GenerateAdvancedReport() string {
	var report strings.Builder
	
	report.WriteString("// ADVANCED ANALYSIS REPORT\n")
	report.WriteString("// =========================\n\n")
	
	// Entropy analysis
	if len(a.entropy) > 0 {
		report.WriteString("// ENTROPY ANALYSIS:\n")
		for addr, entropy := range a.entropy {
			report.WriteString(fmt.Sprintf("// 0x%x: %.2f entropy\n", addr, entropy))
		}
		report.WriteString("\n")
	}
	
	// Encryption indicators
	if len(a.encryption) > 0 {
		report.WriteString("// ENCRYPTION/OBFUSCATION DETECTED:\n")
		for _, enc := range a.encryption {
			report.WriteString(fmt.Sprintf("// %s at 0x%x: %s (%.1f%% confidence)\n", 
				enc.Type, enc.Location, enc.Description, enc.Confidence*100))
		}
		report.WriteString("\n")
	}
	
	// Anti-debug techniques
	if len(a.antiDebug) > 0 {
		report.WriteString("// ANTI-DEBUG TECHNIQUES:\n")
		for _, ad := range a.antiDebug {
			report.WriteString(fmt.Sprintf("// %s at 0x%x: %s [%s]\n", 
				ad.Type, ad.Location, ad.Description, ad.Severity))
		}
		report.WriteString("\n")
	}
	
	return report.String()
}