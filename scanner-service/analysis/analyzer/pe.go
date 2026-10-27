package analyzer

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"math"
	"sort"
	"strings"

	"scanner-service/analysis/evidence"
)

const (
	DefaultPackEntropyThreshold = 7.2
	defaultMaxSections          = 96
	fewImportsThreshold         = 10
	fewImportsMinSize           = 512 * 1024
	megaByte                    = 1024 * 1024
)

var packerSectionNames = map[string]bool{
	"upx0": true, "upx1": true, "upx2": true, "upx!": true,
	".upx": true, ".upx0": true, ".upx1": true,
	".aspack": true, ".adata": true, ".packed": true,
	".petite": true, ".themida": true, ".vmp0": true, ".vmp1": true,
	".enigma1": true, ".enigma2": true, ".mpress1": true, ".mpress2": true,
	".nsp0": true, ".nsp1": true, ".boom": true, ".ccg": true,
	".gentee": true, ".pklst": true, ".spack": true, ".winapi": true,
	".y0da": true, ".rmnet": true,
}

// SuspiciousImports lists Windows APIs that are specific to process injection,
// process hollowing, keylogging and download-and-execute. Broadly used APIs
// (GetProcAddress, LoadLibrary, VirtualAlloc, registry and privilege calls,
// IsDebuggerPresent) are deliberately excluded: they appear in almost every
// legitimate program and drowned out the real signal.
var SuspiciousImports = []string{
	"checkremotedebuggerpresent",
	"createremotethread", "createremotethreadex",
	"getasynckeystate",
	"netuseradd",
	"ntcreatethreadex",
	"ntunmapviewofsection",
	"ntwritevirtualmemory",
	"queueuserapc",
	"rtlcreateuserthread",
	"setthreadcontext",
	"setwindowshookexa", "setwindowshookexw",
	"urldownloadtofilea", "urldownloadtofilew",
	"virtualallocex",
	"virtualprotectex",
	"winexec",
	"writeprocessmemory",
	"zwunmapviewofsection",
}

type PEAnalyzer struct {
	PackEntropyThreshold float64
	Suspicious           map[string]bool
}

func NewPEAnalyzer(entropyThreshold float64) *PEAnalyzer {
	if entropyThreshold <= 0 || entropyThreshold > 8 {
		entropyThreshold = DefaultPackEntropyThreshold
	}

	suspicious := make(map[string]bool, len(SuspiciousImports))
	for _, name := range SuspiciousImports {
		suspicious[strings.ToLower(name)] = true
	}

	return &PEAnalyzer{
		PackEntropyThreshold: entropyThreshold,
		Suspicious:           suspicious,
	}
}

func (a *PEAnalyzer) Name() string { return "pe" }

func (a *PEAnalyzer) Supports(in Input) bool {
	if !hasPEMagic(in.Data) {
		return false
	}

	file, _, err := openPE(in.Data)
	if err != nil {
		return false
	}
	_ = file.Close()

	return true
}

// openPE parses a PE image. debug/pe also reads the COFF symbol table, which the
// Windows loader ignores and packers often corrupt; when that is the only
// problem, the image is re-parsed with the symbol table pointer cleared and
// tampered is true.
func openPE(data []byte) (file *pe.File, tampered bool, err error) {
	file, err = pe.NewFile(bytes.NewReader(data))
	if err == nil || !strings.Contains(err.Error(), "string table") || len(data) < 0x40 {
		return file, false, err
	}

	coff := int(binary.LittleEndian.Uint32(data[0x3C:])) + 4
	if coff < 0x40 || coff+20 > len(data) {
		return nil, false, err
	}

	patched := bytes.Clone(data)
	binary.LittleEndian.PutUint32(patched[coff+8:], 0)  // PointerToSymbolTable
	binary.LittleEndian.PutUint32(patched[coff+12:], 0) // NumberOfSymbols
	file, retryErr := pe.NewFile(bytes.NewReader(patched))
	if retryErr != nil {
		return nil, false, err
	}
	return file, true, nil
}

func (a *PEAnalyzer) Analyze(in Input) (evidence.StaticAnalysis, error) {
	data := in.Data

	file, tampered, err := openPE(data)
	if err != nil {
		return evidence.StaticAnalysis{}, err
	}
	defer file.Close()

	result := evidence.StaticAnalysis{Supported: true, Kind: "pe"}
	result.IsDLL = file.FileHeader.Characteristics&pe.IMAGE_FILE_DLL != 0
	result.Architecture = architectureName(file.FileHeader.Machine)

	var entryPoint uint32
	var directories [16]pe.DataDirectory

	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		result.FileType = "PE32"
		entryPoint = header.AddressOfEntryPoint
		directories = header.DataDirectory
	case *pe.OptionalHeader64:
		result.FileType = "PE32+"
		entryPoint = header.AddressOfEntryPoint
		directories = header.DataDirectory
	default:
		return evidence.StaticAnalysis{Supported: true, Error: "unrecognized PE optional header"}, nil
	}

	// The certificate table is excluded from the generic scan: its CRL/OCSP
	// URLs and DER bytes say nothing about the program itself.
	genericData := data
	result.IsDotNet = directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0

	if pe.IMAGE_DIRECTORY_ENTRY_SECURITY < len(directories) {
		directory := directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		result.HasDigitalSignature = directory.VirtualAddress > 0 && directory.Size > 0
		if table, ok := certificateTable(data, directory.VirtualAddress, directory.Size); ok {
			start := int(directory.VirtualAddress)
			var layoutRef *peSignatureLayout
			if layout, ok := signatureLayout(data, result.FileType == "PE32+", start, len(table)); ok {
				layoutRef = &layout
			}
			if signer, ok := parseSigner(table, data, layoutRef); ok {
				result.SignerSubject = signer.Subject
				result.SignerIssuer = signer.Issuer
				result.SignatureStatus = signer.Status
				// A signature that does not match the file is worse than none:
				// it was copied from another binary or the file was modified.
				if signer.Status == SignatureInvalid {
					result.HasDigitalSignature = false
				}
			}
			genericData = append(bytes.Clone(data[:start]), data[start+len(table):]...)
		}
	}

	hints := map[string]bool{}
	if tampered {
		hints["invalid COFF symbol table pointer"] = true
	}
	maxEntropy := 0.0
	executableSectionSeen := false

	for i, section := range file.Sections {
		if i >= defaultMaxSections {
			break
		}

		sectionData, err := section.Data()
		if err != nil {
			continue
		}

		sectionEntropy := entropy(sectionData)
		writable := section.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0
		executable := section.Characteristics&(pe.IMAGE_SCN_MEM_EXECUTE|pe.IMAGE_SCN_CNT_CODE) != 0

		result.Sections = append(result.Sections, evidence.Section{
			Name:        section.Name,
			Size:        int64(len(sectionData)),
			VirtualSize: int64(section.VirtualSize),
			Entropy:     round2(sectionEntropy),
			Writable:    writable,
			Executable:  executable,
		})

		if sectionEntropy > maxEntropy {
			maxEntropy = sectionEntropy
		}

		if containsOffset(section.VirtualAddress, section.VirtualSize, entryPoint) {
			result.EntryPointSection = section.Name
		}

		if executable {
			if sectionEntropy >= a.PackEntropyThreshold {
				hints["high-entropy executable section"] = true
			}
			if !executableSectionSeen && !containsOffset(section.VirtualAddress, section.VirtualSize, entryPoint) {
				hints["entry point outside the first executable section"] = true
			}
			executableSectionSeen = true
		}

		if packerSectionNames[strings.ToLower(strings.TrimSpace(section.Name))] {
			hints["section name resembles packer"] = true
		}

		// Only executable sections: data sections routinely reserve
		// uninitialized memory (.bss/.data), while packers unpack code into an
		// empty executable section.
		if executable && section.VirtualSize > 0x1000 && int64(section.VirtualSize) > int64(section.Size)*2+0x1000 {
			hints["executable section much larger in memory than on disk"] = true
		}

		if writable && executable {
			hints["writable and executable section"] = true
		}
	}

	result.MaxEntropy = round2(maxEntropy)

	// Overlay: bytes after the last section's raw data (installers and
	// droppers both carry their payload here). genericData already excludes
	// the certificate table, which normally sits at the very end.
	imageEnd := int64(0)
	for _, section := range file.Sections {
		if end := int64(section.Offset) + int64(section.Size); section.Size > 0 && end > imageEnd {
			imageEnd = end
		}
	}
	if imageEnd > 0 && imageEnd < int64(len(genericData)) {
		overlay := genericData[imageEnd:]
		result.OverlaySize = int64(len(overlay))
		result.OverlayEntropy = round2(entropy(overlay))
	}

	symbols, err := file.ImportedSymbols()
	if err == nil {
		result.ImportsCount = len(symbols)
		result.SuspiciousImports = a.matchSuspicious(symbols)
	}

	if result.ImportsCount < fewImportsThreshold && len(data) > fewImportsMinSize {
		hints["very few imports for a large binary"] = true
	}

	for hint := range hints {
		result.PackerHints = append(result.PackerHints, hint)
	}
	sort.Strings(result.PackerHints)
	result.HasPackedSection = len(result.PackerHints) > 0

	result.Generic = ScanGeneric(Input{Data: genericData, Name: in.Name}, GenericOptions{SkipEmbeddedPE: true, Binary: true})

	return result, nil
}

func (a *PEAnalyzer) matchSuspicious(symbols []string) []string {
	if a.Suspicious == nil {
		return nil
	}

	seen := map[string]bool{}
	var matches []string

	for _, symbol := range symbols {
		// debug/pe returns imports as "Function:library.dll".
		name, _, _ := strings.Cut(symbol, ":")
		if !a.Suspicious[strings.ToLower(name)] || seen[name] {
			continue
		}
		seen[name] = true
		matches = append(matches, name)
	}

	sort.Strings(matches)
	return matches
}

func hasPEMagic(data []byte) bool {
	return len(data) >= 2 && data[0] == 'M' && data[1] == 'Z'
}

func containsOffset(start uint32, size uint32, offset uint32) bool {
	if size == 0 {
		return false
	}
	return offset >= start && offset < start+size
}

func architectureName(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86_64"
	case pe.IMAGE_FILE_MACHINE_ARM, pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_IA64:
		return "ia64"
	default:
		return "unknown"
	}
}

// entropy returns the Shannon entropy (0-8) of the given bytes.
func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	total := float64(len(data))
	result := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		result -= p * math.Log2(p)
	}

	return result
}

func round2(value float64) float64 {
	return math.Round(value*100) / 100
}
