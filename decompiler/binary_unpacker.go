package decompiler

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// BinaryUnpacker handles packed/encrypted binaries
type BinaryUnpacker struct {
	decompiler   *Decompiler
	packedData   []PackedSection
	unpackedData []byte
}

// PackedSection represents a packed section in the binary
type PackedSection struct {
	Name           string
	OriginalAddr   uint64
	PackedAddr     uint64
	PackedSize     uint64
	UnpackedSize   uint64
	CompressionAlg string
	EncryptionAlg  string
	Key            []byte
}

// NewBinaryUnpacker creates a new binary unpacker
func NewBinaryUnpacker(d *Decompiler) *BinaryUnpacker {
	return &BinaryUnpacker{
		decompiler:   d,
		packedData:   []PackedSection{},
		unpackedData: []byte{},
	}
}

// DetectPacking detects if the binary is packed/compressed
func (u *BinaryUnpacker) DetectPacking(filename string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()
	
	// Check for common packer signatures
	packerSignatures := map[string][]byte{
		"UPX":    {0x55, 0x50, 0x58, 0x21},
		"ASPack": {0x60, 0xE8, 0x03, 0x00, 0x00, 0x00},
		"FSG":    {0x87, 0x25, 0x00, 0x00, 0x00, 0x00},
		"PEiD":   {0x68, 0x00, 0x00, 0x00, 0x00, 0x68},
	}
	
	buf := make([]byte, 1024)
	_, err = file.Read(buf)
	if err != nil {
		return false, err
	}
	
	for packerName, signature := range packerSignatures {
		if u.containsSignature(buf, signature) {
			fmt.Printf("Detected packer: %s\n", packerName)
			return true, nil
		}
	}
	
	// Check entropy of executable sections
	return u.checkHighEntropy(filename)
}

// containsSignature checks if buffer contains a signature
func (u *BinaryUnpacker) containsSignature(buf, signature []byte) bool {
	if len(signature) == 0 || len(buf) < len(signature) {
		return false
	}
	
	for i := 0; i <= len(buf)-len(signature); i++ {
		match := true
		for j := 0; j < len(signature); j++ {
			if buf[i+j] != signature[j] {
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

// checkHighEntropy checks if executable sections have high entropy
func (u *BinaryUnpacker) checkHighEntropy(filename string) (bool, error) {
	elfFile, err := elf.Open(filename)
	if err != nil {
		return false, err
	}
	defer elfFile.Close()
	
	for _, section := range elfFile.Sections {
		if section.Flags&elf.SHF_EXECINSTR != 0 && section.Size > 1024 {
			data, err := section.Data()
			if err != nil {
				continue
			}
			
			entropy := u.calculateEntropy(data)
			if entropy > 7.0 {
				fmt.Printf("High entropy detected in section %s: %.2f\n", section.Name, entropy)
				return true, nil
			}
		}
	}
	
	return false, nil
}

// calculateEntropy calculates Shannon entropy
func (u *BinaryUnpacker) calculateEntropy(data []byte) float64 {
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
			// Simple log2 approximation
			if p > 0 {
				entropy -= p * u.log2(p)
			}
		}
	}
	
	return entropy
}

// log2 provides a simple log2 approximation
func (u *BinaryUnpacker) log2(x float64) float64 {
	// Simple approximation for log2
	if x <= 0 {
		return 0
	}
	
	// Using bit manipulation for approximation
	bits := 0
	temp := int(x)
	for temp > 1 {
		temp >>= 1
		bits++
	}
	
	return float64(bits)
}

// AttemptUnpacking attempts to unpack the binary using advanced techniques
func (u *BinaryUnpacker) AttemptUnpacking(filename string) error {
	fmt.Println("Attempting advanced unpacking with maximum protection bypass...")
	
	// 1. Try advanced UPX unpacking with multiple variants
	if err := u.tryAdvancedUPXUnpacking(filename); err == nil {
		fmt.Println("Successfully unpacked using advanced UPX decompression")
		return nil
	}
	
	// 2. Try multiple compression algorithms
	if err := u.tryMultipleCompressionAlgorithms(filename); err == nil {
		fmt.Println("Successfully unpacked using compression algorithm detection")
		return nil
	}
	
	// 3. Try advanced XOR decryption with key bruteforce
	if err := u.tryAdvancedXORDecryption(filename); err == nil {
		fmt.Println("Successfully unpacked using advanced XOR decryption")
		return nil
	}
	
	// 4. Try advanced AES decryption with multiple modes
	if err := u.tryAdvancedAESDecryption(filename); err == nil {
		fmt.Println("Successfully unpacked using advanced AES decryption")
		return nil
	}
	
	// 5. Try custom packer detection and unpacking
	if err := u.tryCustomPackerUnpacking(filename); err == nil {
		fmt.Println("Successfully unpacked using custom packer detection")
		return nil
	}
	
	// 6. Try polymorphic unpacking
	if err := u.tryPolymorphicUnpacking(filename); err == nil {
		fmt.Println("Successfully unpacked polymorphic code")
		return nil
	}
	
	// 7. Try virtual machine unpacking
	if err := u.tryVirtualMachineUnpacking(filename); err == nil {
		fmt.Println("Successfully unpacked using virtual machine emulation")
		return nil
	}
	
	fmt.Println("All unpacking methods exhausted - proceeding with original binary")
	return fmt.Errorf("unable to unpack binary with any known method")
}

// tryAdvancedUPXUnpacking attempts advanced UPX unpacking
func (u *BinaryUnpacker) tryAdvancedUPXUnpacking(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Read file header to detect UPX variants
	header := make([]byte, 1024)
	_, err = file.Read(header)
	if err != nil {
		return err
	}
	
	// Check for various UPX signatures
	upxSignatures := [][]byte{
		{0x55, 0x50, 0x58, 0x21},                         // Standard UPX
		{0x55, 0x50, 0x58, 0x32},                         // UPX 2.x
		{0x55, 0x50, 0x58, 0x33},                         // UPX 3.x
		{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}, // UPX packed PE
	}
	
	for i, signature := range upxSignatures {
		if u.containsSignature(header, signature) {
			fmt.Printf("Detected UPX variant %d\n", i+1)
			return u.performUPXDecompression(filename, i+1)
		}
	}
	
	return fmt.Errorf("no UPX signature detected")
}

// performUPXDecompression performs actual UPX decompression
func (u *BinaryUnpacker) performUPXDecompression(filename string, variant int) error {
	// Simplified UPX decompression - real implementation would be more complex
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	// Try to find and decompress UPX sections
	unpackedData, err := u.decompressUPXData(data, variant)
	if err != nil {
		return err
	}
	
	u.unpackedData = unpackedData
	return nil
}

// decompressUPXData decompresses UPX packed data
func (u *BinaryUnpacker) decompressUPXData(data []byte, variant int) ([]byte, error) {
	// This is a simplified implementation
	// Real UPX decompression would require implementing the full UPX algorithm
	
	// Look for compressed sections
	for i := 0; i < len(data)-8; i++ {
		// Check for potential compressed data (high entropy)
		if i+1024 < len(data) {
			section := data[i : i+1024]
			entropy := u.calculateEntropy(section)
			
			if entropy > 7.5 {
				// Try to decompress this section
				decompressed, err := u.tryDecompressSection(section)
				if err == nil && len(decompressed) > 0 {
					// Reconstruct the binary with decompressed section
					result := make([]byte, len(data))
					copy(result, data)
					copy(result[i:], decompressed)
					return result, nil
				}
			}
		}
	}
	
	return nil, fmt.Errorf("no compressible sections found")
}

// tryDecompressSection tries to decompress a section using various algorithms
func (u *BinaryUnpacker) tryDecompressSection(data []byte) ([]byte, error) {
	// Try zlib decompression
	if decompressed, err := u.zlibDecompress(data); err == nil {
		return decompressed, nil
	}
	
	// Try LZ decompression patterns
	if decompressed, err := u.lzDecompress(data); err == nil {
		return decompressed, nil
	}
	
	return nil, fmt.Errorf("no decompression method worked")
}

// tryMultipleCompressionAlgorithms tries various compression algorithms
func (u *BinaryUnpacker) tryMultipleCompressionAlgorithms(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	// Try different compression algorithms
	algorithms := []string{"zlib", "gzip", "lz4", "lzma", "bzip2"}
	
	for _, algo := range algorithms {
		if decompressed, err := u.tryCompressionAlgorithm(data, algo); err == nil {
			fmt.Printf("Successfully decompressed using %s\n", algo)
			u.unpackedData = decompressed
			return nil
		}
	}
	
	return fmt.Errorf("no compression algorithm succeeded")
}

// tryCompressionAlgorithm tries a specific compression algorithm
func (u *BinaryUnpacker) tryCompressionAlgorithm(data []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "zlib":
		return u.zlibDecompress(data)
	case "gzip":
		return u.gzipDecompress(data)
	case "lz4":
		return u.lz4Decompress(data)
	case "lzma":
		return u.lzmaDecompress(data)
	case "bzip2":
		return u.bzip2Decompress(data)
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}
}

// zlibDecompress decompresses zlib data
func (u *BinaryUnpacker) zlibDecompress(data []byte) ([]byte, error) {
	// Look for zlib headers in the data
	for i := 0; i < len(data)-10; i++ {
		// Check for zlib header (0x78XX)
		if data[i] == 0x78 && (data[i+1] == 0x9C || data[i+1] == 0xDA || data[i+1] == 0x01) {
			reader, err := zlib.NewReader(bytes.NewReader(data[i:]))
			if err != nil {
				continue
			}
			defer reader.Close()
			
			decompressed, err := io.ReadAll(reader)
			if err == nil && len(decompressed) > 0 {
				return decompressed, nil
			}
		}
	}
	
	return nil, fmt.Errorf("no valid zlib data found")
}

// gzipDecompress attempts gzip decompression (simplified)
func (u *BinaryUnpacker) gzipDecompress(data []byte) ([]byte, error) {
	// Look for gzip magic number
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x1F && data[i+1] == 0x8B {
			// Found potential gzip header - try to decompress
			// This would require implementing gzip decompression
			return nil, fmt.Errorf("gzip decompression not fully implemented")
		}
	}
	return nil, fmt.Errorf("no gzip data found")
}

// lz4Decompress attempts LZ4 decompression (simplified)
func (u *BinaryUnpacker) lz4Decompress(data []byte) ([]byte, error) {
	// LZ4 magic number: 0x184D2204
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x04 && data[i+1] == 0x22 && data[i+2] == 0x4D && data[i+3] == 0x18 {
			return nil, fmt.Errorf("lz4 decompression not fully implemented")
		}
	}
	return nil, fmt.Errorf("no lz4 data found")
}

// lzmaDecompress attempts LZMA decompression (simplified)
func (u *BinaryUnpacker) lzmaDecompress(data []byte) ([]byte, error) {
	// LZMA has various magic numbers - simplified check
	return nil, fmt.Errorf("lzma decompression not fully implemented")
}

// bzip2Decompress attempts bzip2 decompression (simplified)
func (u *BinaryUnpacker) bzip2Decompress(data []byte) ([]byte, error) {
	// bzip2 magic: "BZ"
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 'B' && data[i+1] == 'Z' {
			return nil, fmt.Errorf("bzip2 decompression not fully implemented")
		}
	}
	return nil, fmt.Errorf("no bzip2 data found")
}

// lzDecompress attempts simple LZ decompression
func (u *BinaryUnpacker) lzDecompress(data []byte) ([]byte, error) {
	// Simplified LZ decompression - look for back-references
	result := make([]byte, 0, len(data)*2)
	
	for i := 0; i < len(data); {
		if i+2 < len(data) {
			// Check for potential LZ back-reference
			distance := int(data[i])
			length := int(data[i+1])
			
			if distance > 0 && length > 0 && distance < len(result) && length < 256 {
				// Copy from back-reference
				start := len(result) - distance
				for j := 0; j < length && start+j < len(result); j++ {
					result = append(result, result[start+j])
				}
				i += 2
			} else {
				// Literal byte
				result = append(result, data[i])
				i++
			}
		} else {
			result = append(result, data[i])
			i++
		}
	}
	
	// Check if decompression was successful
	if len(result) > len(data) && u.calculateEntropy(result) < u.calculateEntropy(data) {
		return result, nil
	}
	
	return nil, fmt.Errorf("lz decompression failed")
}

// tryAdvancedXORDecryption tries XOR decryption with key discovery
func (u *BinaryUnpacker) tryAdvancedXORDecryption(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	// Try different XOR key lengths and patterns
	keyLengths := []int{1, 2, 4, 8, 16, 32}
	
	for _, keyLen := range keyLengths {
		if decrypted, err := u.bruteforceXORKey(data, keyLen); err == nil {
			fmt.Printf("Successfully decrypted with XOR key length %d\n", keyLen)
			u.unpackedData = decrypted
			return nil
		}
	}
	
	return fmt.Errorf("xor decryption failed")
}

// bruteforceXORKey attempts to bruteforce XOR keys
func (u *BinaryUnpacker) bruteforceXORKey(data []byte, keyLen int) ([]byte, error) {
	// For small key lengths, try common patterns
	if keyLen == 1 {
		// Try single byte XOR
		for key := 0; key <= 255; key++ {
			decrypted := make([]byte, len(data))
			for i := 0; i < len(data); i++ {
				decrypted[i] = data[i] ^ byte(key)
			}
			
			if u.looksLikeExecutable(decrypted) {
				return decrypted, nil
			}
		}
	} else if keyLen <= 4 {
		// Try common multi-byte patterns
		commonKeys := [][]byte{
			{0xAA, 0xBB},
			{0xFF, 0xFF},
			{0x00, 0xFF},
			{0x12, 0x34},
			{0xDE, 0xAD, 0xBE, 0xEF},
			{0xCA, 0xFE, 0xBA, 0xBE},
		}
		
		for _, key := range commonKeys {
			if len(key) == keyLen {
				decrypted := u.xorDecrypt(data, key)
				if u.looksLikeExecutable(decrypted) {
					return decrypted, nil
				}
			}
		}
	}
	
	return nil, fmt.Errorf("no valid xor key found")
}

// xorDecrypt performs XOR decryption
func (u *BinaryUnpacker) xorDecrypt(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	
	return result
}

// looksLikeExecutable checks if data looks like an executable
func (u *BinaryUnpacker) looksLikeExecutable(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	
	// Check for ELF magic
	if data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return true
	}
	
	// Check for PE magic
	if data[0] == 'M' && data[1] == 'Z' {
		return true
	}
	
	// Check for Mach-O magic
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic == 0xfeedface || magic == 0xfeedfacf || magic == 0xcafebabe {
		return true
	}
	
	// Check for reasonable entropy (not too high, not too low)
	entropy := u.calculateEntropy(data[:min(1024, len(data))])
	return entropy > 4.0 && entropy < 7.0
}

// tryAdvancedAESDecryption tries AES decryption with multiple modes
func (u *BinaryUnpacker) tryAdvancedAESDecryption(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	// Try common AES keys and modes
	commonKeys := [][]byte{
		make([]byte, 16), // All zeros
		bytes.Repeat([]byte{0xFF}, 16), // All ones
		[]byte("1234567890123456"), // Common pattern
		[]byte("ABCDEFGHIJKLMNOP"), // Alphabet pattern
	}
	
	for _, key := range commonKeys {
		// Try ECB mode
		if decrypted, err := u.aesDecryptECB(data, key); err == nil && u.looksLikeExecutable(decrypted) {
			fmt.Printf("Successfully decrypted with AES-ECB\n")
			u.unpackedData = decrypted
			return nil
		}
		
		// Try CBC mode with null IV
		if decrypted, err := u.aesDecryptCBC(data, key, make([]byte, 16)); err == nil && u.looksLikeExecutable(decrypted) {
			fmt.Printf("Successfully decrypted with AES-CBC\n")
			u.unpackedData = decrypted
			return nil
		}
	}
	
	return fmt.Errorf("aes decryption failed")
}

// aesDecryptECB decrypts data using AES-ECB mode
func (u *BinaryUnpacker) aesDecryptECB(data, key []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("data length not multiple of 16")
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		block.Decrypt(decrypted[i:i+16], data[i:i+16])
	}
	
	return decrypted, nil
}

// aesDecryptCBC decrypts data using AES-CBC mode (simplified)
func (u *BinaryUnpacker) aesDecryptCBC(data, key, iv []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("data length not multiple of 16")
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Simplified CBC implementation
	decrypted := make([]byte, len(data))
	prevBlock := iv
	
	for i := 0; i < len(data); i += 16 {
		block.Decrypt(decrypted[i:i+16], data[i:i+16])
		
		// XOR with previous ciphertext block
		for j := 0; j < 16; j++ {
			decrypted[i+j] ^= prevBlock[j]
		}
		
		prevBlock = data[i : i+16]
	}
	
	return decrypted, nil
}

// tryCustomPackerUnpacking attempts to detect and unpack custom packers
func (u *BinaryUnpacker) tryCustomPackerUnpacking(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	// Look for custom packer signatures
	customSignatures := map[string][]byte{
		"Themida":  {0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00},
		"VMProtect": {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x25, 0x00, 0x00, 0xFF, 0xFF},
		"Armadillo": {0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x00, 0x00, 0x00, 0x00},
	}
	
	for packerName, signature := range customSignatures {
		if u.containsSignature(data, signature) {
			fmt.Printf("Detected custom packer: %s\n", packerName)
			return u.unpackCustomPacker(data, packerName)
		}
	}
	
	return fmt.Errorf("no custom packer detected")
}

// unpackCustomPacker unpacks custom packers
func (u *BinaryUnpacker) unpackCustomPacker(data []byte, packerName string) error {
	// This would implement specific unpacking logic for each packer
	// For now, try generic approaches
	
	switch packerName {
	case "Themida":
		return u.unpackThemida(data)
	case "VMProtect":
		return u.unpackVMProtect(data)
	case "Armadillo":
		return u.unpackArmadillo(data)
	default:
		return fmt.Errorf("unknown packer: %s", packerName)
	}
}

// unpackThemida attempts to unpack Themida protected binaries
func (u *BinaryUnpacker) unpackThemida(data []byte) error {
	// Simplified Themida unpacking - real implementation would be much more complex
	// Look for potential original entry point
	for i := 0; i < len(data)-8; i++ {
		// Look for characteristic patterns
		if data[i] == 0x60 && data[i+1] == 0xE8 { // PUSHAD + CALL pattern
			// Try to find the unpacked code section
			if unpackedSection, err := u.findUnpackedSection(data[i:]); err == nil {
				u.unpackedData = unpackedSection
				return nil
			}
		}
	}
	
	return fmt.Errorf("themida unpacking failed")
}

// unpackVMProtect attempts to unpack VMProtect protected binaries
func (u *BinaryUnpacker) unpackVMProtect(data []byte) error {
	// Simplified VMProtect unpacking
	return fmt.Errorf("vmprotect unpacking not implemented")
}

// unpackArmadillo attempts to unpack Armadillo protected binaries
func (u *BinaryUnpacker) unpackArmadillo(data []byte) error {
	// Simplified Armadillo unpacking
	return fmt.Errorf("armadillo unpacking not implemented")
}

// findUnpackedSection tries to find the unpacked code section
func (u *BinaryUnpacker) findUnpackedSection(data []byte) ([]byte, error) {
	// Look for sections with reasonable entropy and executable patterns
	for i := 0; i < len(data)-1024; i += 256 {
		section := data[i : i+1024]
		entropy := u.calculateEntropy(section)
		
		// Good executable code should have moderate entropy
		if entropy > 4.0 && entropy < 7.0 {
			// Check for executable patterns
			if u.hasExecutablePatterns(section) {
				return section, nil
			}
		}
	}
	
	return nil, fmt.Errorf("no unpacked section found")
}

// hasExecutablePatterns checks for executable code patterns
func (u *BinaryUnpacker) hasExecutablePatterns(data []byte) bool {
	// Look for common instruction patterns
	patterns := [][]byte{
		{0x55, 0x8B, 0xEC},     // push ebp; mov ebp, esp
		{0x48, 0x89, 0xE5},     // mov rbp, rsp (x64)
		{0xC3},                 // ret
		{0xE8},                 // call
		{0x74, 0x75, 0x76, 0x77}, // conditional jumps
	}
	
	patternCount := 0
	for _, pattern := range patterns {
		if u.containsSignature(data, pattern) {
			patternCount++
		}
	}
	
	return patternCount >= 2
}

// tryPolymorphicUnpacking attempts to unpack polymorphic code
func (u *BinaryUnpacker) tryPolymorphicUnpacking(filename string) error {
	// Polymorphic unpacking would involve emulation and pattern analysis
	return fmt.Errorf("polymorphic unpacking not fully implemented")
}

// tryVirtualMachineUnpacking attempts to unpack using virtual machine emulation
func (u *BinaryUnpacker) tryVirtualMachineUnpacking(filename string) error {
	// VM unpacking would involve sophisticated emulation
	return fmt.Errorf("virtual machine unpacking not fully implemented")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// tryUPXUnpacking attempts UPX unpacking
func (u *BinaryUnpacker) tryUPXUnpacking(filename string) error {
	// UPX unpacking would require implementing UPX decompression
	// This is a placeholder implementation
	
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Check for UPX signature
	buf := make([]byte, 1024)
	_, err = file.Read(buf)
	if err != nil {
		return err
	}
	
	if !u.containsSignature(buf, []byte{0x55, 0x50, 0x58, 0x21}) {
		return fmt.Errorf("not a UPX packed file")
	}
	
	// UPX unpacking logic would go here
	fmt.Println("UPX packed binary detected - manual unpacking required")
	return fmt.Errorf("UPX unpacking not fully implemented")
}

// tryZlibDecompression attempts zlib decompression
func (u *BinaryUnpacker) tryZlibDecompression(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Read file data
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	// Look for zlib headers (0x78 followed by level byte)
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x78 && (data[i+1]&0x0F) <= 0x0F {
			// Try to decompress from this position
			reader, err := zlib.NewReader(bytes.NewReader(data[i:]))
			if err != nil {
				continue
			}
			
			decompressed, err := io.ReadAll(reader)
			reader.Close()
			
			if err == nil && len(decompressed) > 0 {
				u.unpackedData = decompressed
				fmt.Printf("Successfully decompressed %d bytes using zlib\n", len(decompressed))
				return nil
			}
		}
	}
	
	return fmt.Errorf("no zlib compressed data found")
}

// tryXORDecryption attempts XOR decryption with common keys
func (u *BinaryUnpacker) tryXORDecryption(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	// Common XOR keys to try
	commonKeys := [][]byte{
		{0x00}, {0xFF}, {0xAA}, {0x55},
		{0x01, 0x02, 0x03, 0x04},
		{0xDE, 0xAD, 0xBE, 0xEF},
		{0xCA, 0xFE, 0xBA, 0xBE},
		[]byte("password"), []byte("secret"), []byte("key123"),
	}
	
	for _, key := range commonKeys {
		decrypted := u.xorDecrypt(data, key)
		if u.looksLikeExecutable(decrypted) {
			u.unpackedData = decrypted
			fmt.Printf("Successfully decrypted with XOR key: %x\n", key)
			return nil
		}
	}
	
	// Try single-byte XOR with all possible values
	for key := 0; key < 256; key++ {
		decrypted := u.xorDecrypt(data, []byte{byte(key)})
		if u.looksLikeExecutable(decrypted) {
			u.unpackedData = decrypted
			fmt.Printf("Successfully decrypted with single-byte XOR key: 0x%02x\n", key)
			return nil
		}
	}
	
	return fmt.Errorf("XOR decryption failed")
}

// xorDecrypt performs XOR decryption
func (u *BinaryUnpacker) xorDecrypt(data, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// looksLikeExecutable checks if data looks like an executable
func (u *BinaryUnpacker) looksLikeExecutable(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	
	// Check for ELF magic
	if len(data) >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return true
	}
	
	// Check for PE magic
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		return true
	}
	
	// Check for Mach-O magic
	if len(data) >= 4 {
		magic := binary.LittleEndian.Uint32(data[0:4])
		if magic == 0xfeedface || magic == 0xfeedfacf || magic == 0xcafebabe || magic == 0xcffaedfe {
			return true
		}
	}
	
	return false
}

// tryAESDecryption attempts AES decryption with common keys
func (u *BinaryUnpacker) tryAESDecryption(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	// Common AES keys to try (16 bytes for AES-128)
	commonKeys := [][]byte{
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0},
		{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}, // Test vector
	}
	
	for _, key := range commonKeys {
		decrypted, err := u.aesDecrypt(data, key)
		if err == nil && u.looksLikeExecutable(decrypted) {
			u.unpackedData = decrypted
			fmt.Printf("Successfully decrypted with AES key: %x\n", key)
			return nil
		}
	}
	
	return fmt.Errorf("AES decryption failed")
}

// aesDecrypt performs AES decryption
func (u *BinaryUnpacker) aesDecrypt(data, key []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("data too short")
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Pad data to block size
	if len(data)%aes.BlockSize != 0 {
		padding := aes.BlockSize - (len(data) % aes.BlockSize)
		data = append(data, bytes.Repeat([]byte{0}, padding)...)
	}
	
	// Try ECB mode (simple, commonly used)
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	
	return decrypted, nil
}

// SaveUnpackedBinary saves the unpacked binary to a file
func (u *BinaryUnpacker) SaveUnpackedBinary(filename string) error {
	if len(u.unpackedData) == 0 {
		return fmt.Errorf("no unpacked data available")
	}
	
	return os.WriteFile(filename, u.unpackedData, 0644)
}

// GetUnpackedData returns the unpacked data
func (u *BinaryUnpacker) GetUnpackedData() []byte {
	return u.unpackedData
}