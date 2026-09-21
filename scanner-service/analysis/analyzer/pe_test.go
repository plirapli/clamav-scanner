package analyzer

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestEntropy(t *testing.T) {
	if got := entropy(nil); got != 0 {
		t.Fatalf("empty entropy = %v", got)
	}
	if got := entropy([]byte{0, 0, 0, 0}); got != 0 {
		t.Fatalf("constant entropy = %v", got)
	}

	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	if got := entropy(uniform); math.Abs(got-8) > 0.001 {
		t.Fatalf("uniform entropy = %v, want 8", got)
	}
}

func TestPEAnalyzerSupports(t *testing.T) {
	a := NewPEAnalyzer(0)

	if a.Supports([]byte("plain text, not a PE")) {
		t.Fatal("text file must not be supported")
	}
	if !a.Supports(minimalPE(".text", []byte{0x90, 0x90}, 0x60000020)) {
		t.Fatal("minimal PE must be supported")
	}
}

func TestPEAnalyzerLowEntropy(t *testing.T) {
	a := NewPEAnalyzer(0)
	result, err := a.Analyze(minimalPE(".text", make([]byte, 4096), 0x60000020))
	if err != nil {
		t.Fatal(err)
	}

	if !result.Supported || result.FileType != "PE32" || result.Architecture != "x86" {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	if result.HasPackedSection {
		t.Fatalf("zeroed section must not be packed: %+v", result.PackerHints)
	}
	if result.HasDigitalSignature {
		t.Fatal("fixture has no signature")
	}
	if result.EntryPointSection != ".text" {
		t.Fatalf("entry point section = %q", result.EntryPointSection)
	}
	if len(result.Sections) != 1 || result.Sections[0].Name != ".text" {
		t.Fatalf("unexpected sections: %+v", result.Sections)
	}
}

func TestPEAnalyzerHighEntropyIsPacked(t *testing.T) {
	a := NewPEAnalyzer(0)

	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i)
	}

	result, err := a.Analyze(minimalPE(".text", data, 0xE0000020))
	if err != nil {
		t.Fatal(err)
	}

	if result.MaxEntropy < 7.2 {
		t.Fatalf("max entropy = %v", result.MaxEntropy)
	}
	if !result.HasPackedSection {
		t.Fatalf("expected packed hints, got %+v", result.PackerHints)
	}
}

func TestRegistryUnsupported(t *testing.T) {
	registry := NewRegistry(NewPEAnalyzer(0))
	result := registry.Analyze([]byte("plain text"))
	if result.Supported {
		t.Fatal("expected unsupported result")
	}
}

// minimalPE builds a syntactically valid PE32 image with one section so the
// analyzer can be tested without shipping binary fixtures.
func minimalPE(sectionName string, sectionData []byte, sectionCharacteristics uint32) []byte {
	const (
		dosHeaderSize  = 0x80
		optHeaderSize  = 224
		sectionHdrSize = 40
		fileAlign      = 0x200
		sectionAlign   = 0x1000
		sectionRVA     = 0x1000
		rawOffset      = 0x200
	)

	rawSize := alignUp(int64(len(sectionData)), fileAlign)
	file := make([]byte, rawOffset+int(rawSize))

	copy(file[0:2], "MZ")
	binary.LittleEndian.PutUint32(file[0x3C:], dosHeaderSize)

	copy(file[dosHeaderSize:], "PE\x00\x00")
	coffOffset := dosHeaderSize + 4
	binary.LittleEndian.PutUint16(file[coffOffset:], 0x014c) // IMAGE_FILE_MACHINE_I386
	binary.LittleEndian.PutUint16(file[coffOffset+2:], 1)    // NumberOfSections
	binary.LittleEndian.PutUint16(file[coffOffset+16:], optHeaderSize)
	binary.LittleEndian.PutUint16(file[coffOffset+18:], 0x0102) // executable, 32-bit

	optOffset := coffOffset + 20
	binary.LittleEndian.PutUint16(file[optOffset:], 0x10b)             // PE32
	binary.LittleEndian.PutUint32(file[optOffset+0x10:], sectionRVA)   // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(file[optOffset+0x1C:], 0x400000)     // ImageBase
	binary.LittleEndian.PutUint32(file[optOffset+0x20:], sectionAlign) // SectionAlignment
	binary.LittleEndian.PutUint32(file[optOffset+0x24:], fileAlign)    // FileAlignment
	binary.LittleEndian.PutUint32(file[optOffset+0x38:], sectionAlign+uint32(rawSize))
	binary.LittleEndian.PutUint32(file[optOffset+0x3C:], rawOffset) // SizeOfHeaders
	binary.LittleEndian.PutUint32(file[optOffset+0x5C:], 16)        // NumberOfRvaAndSizes

	sectionOffset := optOffset + optHeaderSize
	copy(file[sectionOffset:], sectionName)
	binary.LittleEndian.PutUint32(file[sectionOffset+8:], uint32(len(sectionData))) // VirtualSize
	binary.LittleEndian.PutUint32(file[sectionOffset+12:], sectionRVA)              // VirtualAddress
	binary.LittleEndian.PutUint32(file[sectionOffset+16:], uint32(rawSize))         // SizeOfRawData
	binary.LittleEndian.PutUint32(file[sectionOffset+20:], rawOffset)               // PointerToRawData
	binary.LittleEndian.PutUint32(file[sectionOffset+36:], sectionCharacteristics)

	copy(file[rawOffset:], sectionData)

	return file
}

func alignUp(value int64, alignment int64) int64 {
	if value <= 0 {
		return alignment
	}
	return (value + alignment - 1) / alignment * alignment
}
