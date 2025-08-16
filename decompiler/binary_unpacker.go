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

// AttemptUnpacking attempts to unpack the binary
func (u *BinaryUnpacker) AttemptUnpacking(filename string) error {
	// Try different unpacking methods
	if err := u.tryUPXUnpacking(filename); err == nil {
		return nil
	}
	
	if err := u.tryZlibDecompression(filename); err == nil {
		return nil
	}
	
	if err := u.tryXORDecryption(filename); err == nil {
		return nil
	}
	
	if err := u.tryAESDecryption(filename); err == nil {
		return nil
	}
	
	return fmt.Errorf("unable to unpack binary")
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