package analyzer

import (
	"bytes"
	"debug/pe"
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
	".y0da": true, ".rmnet": true, ".nsis": true, ".itext": true,
}

// SuspiciousImports is a curated subset of Windows APIs commonly abused by
// malware (process injection, anti-debugging, persistence, networking).
var SuspiciousImports = []string{
	"adjusttokenprivileges",
	"checkremotedebuggerpresent",
	"createprocessa", "createprocessw",
	"createremotethread",
	"createservicea", "createservicew",
	"cryptdecrypt", "cryptencrypt", "cryptgenkey",
	"getasynckeystate",
	"getcomputernamea", "getcomputernamew",
	"getprocadress",
	"getthreadcontext",
	"isdebuggerpresent",
	"loadlibrarya", "loadlibraryw",
	"lookupprivilegevaluea", "lookupprivilegevaluew",
	"mapviewoffile",
	"netuseradd",
	"ntcreatethreadex",
	"ntunmapviewofsection",
	"openprocess",
	"outputdebugstringa", "outputdebugstringw",
	"process32first", "process32next",
	"queueuserapc",
	"readprocessmemory",
	"regcreatekeyexa", "regcreatekeyexw",
	"regsetvalueexa", "regsetvalueexw",
	"resumethread",
	"rtlmovememory",
	"setthreadcontext",
	"setwindowshookexa", "setwindowshookexw",
	"shellExecuteA", "shellexecutew",
	"startservicea", "startservicew",
	"suspendthread",
	"terminateprocess",
	"urldownloadtofilea", "urldownloadtofilew",
	"virtualalloc", "virtualallocex",
	"virtualprotect", "virtualprotectex",
	"winexec",
	"writeprocessmemory",
	"wtsgetactiveconsoleSessionid",
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

func (a *PEAnalyzer) Supports(data []byte) bool {
	if !hasPEMagic(data) {
		return false
	}

	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return false
	}
	_ = file.Close()

	return true
}

func (a *PEAnalyzer) Analyze(data []byte) (evidence.StaticAnalysis, error) {
	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return evidence.StaticAnalysis{}, err
	}
	defer file.Close()

	result := evidence.StaticAnalysis{Supported: true}
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

	if pe.IMAGE_DIRECTORY_ENTRY_SECURITY < len(directories) {
		directory := directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		result.HasDigitalSignature = directory.VirtualAddress > 0 && directory.Size > 0
	}

	hints := map[string]bool{}
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

		if section.VirtualSize > 0x1000 && int64(section.VirtualSize) > int64(section.Size)*2+0x1000 {
			hints["virtual size much larger than raw size"] = true
		}

		if writable && executable {
			hints["writable and executable section"] = true
		}
	}

	result.MaxEntropy = round2(maxEntropy)

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

	return result, nil
}

func (a *PEAnalyzer) matchSuspicious(symbols []string) []string {
	if a.Suspicious == nil {
		return nil
	}

	seen := map[string]bool{}
	var matches []string

	for _, symbol := range symbols {
		name := symbol
		if index := strings.LastIndex(symbol, ":"); index >= 0 {
			name = symbol[index+1:]
		}
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
