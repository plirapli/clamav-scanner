package analyzer

import (
	"archive/zip"
	"bytes"
	"path"
	"strings"

	"scanner-service/analysis/evidence"
)

const maxArchiveEntries = 200

var executableExtensions = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".sys": true, ".com": true, ".pif": true,
	".bat": true, ".cmd": true, ".ps1": true, ".js": true, ".vbs": true, ".lnk": true, ".hta": true,
}

type ArchiveAnalyzer struct {
	Options GenericOptions
}

func NewArchiveAnalyzer() *ArchiveAnalyzer {
	return &ArchiveAnalyzer{Options: DefaultGenericOptions()}
}

func (a *ArchiveAnalyzer) Name() string { return "archive" }

func (a *ArchiveAnalyzer) Supports(in Input) bool {
	switch DetectMagic(in.Data) {
	case "zip", "rar", "7z", "gzip", "cab":
		return true
	default:
		return false
	}
}

func (a *ArchiveAnalyzer) Analyze(in Input) (evidence.StaticAnalysis, error) {
	g := evidence.GenericEvidence{
		MagicType:   DetectMagic(in.Data),
		FileEntropy: round2(entropy(in.Data)),
	}

	if g.MagicType == "zip" {
		if reader, err := zip.NewReader(bytes.NewReader(in.Data), int64(len(in.Data))); err == nil {
			for index, file := range reader.File {
				if index >= maxArchiveEntries {
					break
				}

				name := file.Name
				base := strings.ToLower(path.Base(name))

				if executableExtensions[strings.ToLower(path.Ext(base))] {
					g.NestedExecutables = append(g.NestedExecutables, name)
				}
				if strings.Contains(name, "../") || strings.Contains(name, "..\\") {
					g.SuspiciousStrings = append(g.SuspiciousStrings, "path traversal: "+name)
				}
				if file.Flags&0x1 != 0 {
					g.Encrypted = true
					g.SuspiciousStrings = append(g.SuspiciousStrings, "encrypted entry")
				}
				if hasDoubleExtension(base) {
					g.SuspiciousStrings = append(g.SuspiciousStrings, "double extension: "+base)
				}
			}
		} else {
			g.Encrypted = true
			g.SuspiciousStrings = append(g.SuspiciousStrings, "unreadable zip")
		}
	}

	g.URLs = extractURLs(in.Data, a.Options.MaxURLs)

	return evidence.StaticAnalysis{Kind: "archive", Generic: g}, nil
}

func hasDoubleExtension(name string) bool {
	parts := strings.Split(name, ".")
	return len(parts) >= 3 && executableExtensions["."+parts[len(parts)-1]]
}
