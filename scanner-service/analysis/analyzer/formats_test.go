package analyzer

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"scanner-service/analysis/evidence"
)

func buildZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buffer.Bytes()
}

func TestGenericFindsEmbeddedPE(t *testing.T) {
	data := append([]byte("invoice attachment - open with care\n"), minimalPE(".text", make([]byte, 2048), 0x60000020)...)

	generic := ScanGeneric(Input{Data: data, Name: "invoice.txt"}, DefaultGenericOptions())
	if !generic.EmbeddedPE {
		t.Fatalf("expected embedded PE, got %+v", generic)
	}
	if !containsString(generic.EmbeddedTypes, "pe") {
		t.Fatalf("expected pe in embedded types: %v", generic.EmbeddedTypes)
	}
}

func TestGenericExtractsURLsAndBase64(t *testing.T) {
	longBase64 := strings.Repeat("QUJDREVGRw", 12)
	data := []byte("visit https://example.com/a and http://evil.test/b?x=1\npayload=" + longBase64)

	generic := ScanGeneric(Input{Data: data, Name: "notes.txt"}, DefaultGenericOptions())
	if len(generic.URLs) != 2 {
		t.Fatalf("expected 2 URLs, got %v", generic.URLs)
	}
	if len(generic.ObfuscationHints) == 0 {
		t.Fatal("expected base64 obfuscation hint")
	}
}

func TestRegistryPromotesUnknownWithSignals(t *testing.T) {
	registry := NewRegistry(NewPEAnalyzer(0))
	data := append([]byte("plain text prefix "), minimalPE(".text", make([]byte, 1024), 0x60000020)...)

	result := registry.Analyze(Input{Data: data, Name: "unknown.bin"})
	if !result.Supported || result.Kind != "generic" {
		t.Fatalf("expected generic supported result, got %+v", result)
	}
	if !result.Generic.EmbeddedPE {
		t.Fatal("expected embedded PE signal")
	}
}

func TestPDFAnalyzer(t *testing.T) {
	pdf := []byte("%PDF-1.7\n1 0 obj\n<< /OpenAction 2 0 R /JavaScript (app.alert(1)) /EmbeddedFile (payload) >>\nhttp://evil.test/x\ntrailer\n%%EOF")

	analyzer := NewPDFAnalyzer()
	if !analyzer.Supports(Input{Data: pdf, Name: "doc.pdf"}) {
		t.Fatal("expected PDF support")
	}

	result, err := analyzer.Analyze(Input{Data: pdf, Name: "doc.pdf"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "pdf" {
		t.Fatalf("kind = %q", result.Kind)
	}
	if !result.Generic.HasJavaScript || !result.Generic.AutoExec {
		t.Fatalf("expected JS + auto-exec, got %+v", result.Generic)
	}
	if len(result.Generic.EmbeddedTypes) == 0 {
		t.Fatal("expected embedded file evidence")
	}
	if len(result.Generic.URLs) != 1 {
		t.Fatalf("expected 1 URL, got %v", result.Generic.URLs)
	}
}

func TestOfficeAnalyzerOOXML(t *testing.T) {
	data := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types/>`),
		"word/document.xml":   []byte(`<w:invokeMacro/>`),
		"word/vbaProject.bin": []byte{0x01, 0x02, 0x03},
		"word/_rels/document.xml.rels": []byte(
			`<Relationships><Relationship Id="r1" Target="http://evil.test/payload.dotm" TargetMode="External"/></Relationships>`,
		),
	})

	analyzer := NewOfficeAnalyzer()
	if !analyzer.Supports(Input{Data: data, Name: "report.docx"}) {
		t.Fatal("expected office support")
	}

	result, err := analyzer.Analyze(Input{Data: data, Name: "report.docx"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Generic.HasMacros {
		t.Fatalf("expected macros, got %+v", result.Generic)
	}
	if len(result.Generic.ExternalTargets) != 1 {
		t.Fatalf("expected 1 external target, got %v", result.Generic.ExternalTargets)
	}
}

func TestOfficeAnalyzerDetectsDDE(t *testing.T) {
	data := buildZip(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types/>`),
		"word/document.xml":   []byte(`<w:fldChar/><w:instrText>INCLUDETEXT "\\\\evil\\share\\doc.docx"</w:instrText>`),
	})

	result, err := NewOfficeAnalyzer().Analyze(Input{Data: data, Name: "dde.docx"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Generic.AutoExec {
		t.Fatalf("expected DDE auto-exec, got %+v", result.Generic)
	}
}

func TestArchiveAnalyzer(t *testing.T) {
	data := buildZip(t, map[string][]byte{
		"docs/readme.txt": []byte("hello"),
		"setup.exe":       []byte("MZ fake"),
		"../escape.txt":   []byte("traversal"),
	})

	analyzer := NewArchiveAnalyzer()
	if !analyzer.Supports(Input{Data: data, Name: "bundle.zip"}) {
		t.Fatal("expected archive support")
	}

	result, err := analyzer.Analyze(Input{Data: data, Name: "bundle.zip"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Generic.NestedExecutables) != 1 || result.Generic.NestedExecutables[0] != "setup.exe" {
		t.Fatalf("nested executables = %v", result.Generic.NestedExecutables)
	}
	if len(result.Generic.SuspiciousStrings) == 0 {
		t.Fatal("expected traversal evidence")
	}
}

func TestScriptAnalyzer(t *testing.T) {
	longBase64 := strings.Repeat("QUJDREVGRw", 12)
	script := []byte("var payload = \"" + longBase64 + "\";\nWScript.Shell.Run(eval(\"x\"));\n")

	analyzer := NewScriptAnalyzer()
	if !analyzer.Supports(Input{Data: script, Name: "dropper.js"}) {
		t.Fatal("expected script support")
	}

	result, err := analyzer.Analyze(Input{Data: script, Name: "dropper.js"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "script" {
		t.Fatalf("kind = %q", result.Kind)
	}
	if !result.Generic.HasJavaScript {
		t.Fatal("expected javascript flag")
	}
	if len(result.Generic.ObfuscationHints) == 0 {
		t.Fatal("expected obfuscation hints")
	}
	foundEval := false
	for _, value := range result.Generic.SuspiciousStrings {
		if value == "eval" {
			foundEval = true
		}
	}
	if !foundEval {
		t.Fatalf("expected eval marker, got %v", result.Generic.SuspiciousStrings)
	}
}

func TestArchiveAnalyzerEncryptedEntries(t *testing.T) {
	data := markZipEncrypted(t, buildZip(t, map[string][]byte{
		"secret/payroll.xlsx": []byte("fake spreadsheet"),
	}))

	analyzer := NewArchiveAnalyzer()
	if !analyzer.Supports(Input{Data: data, Name: "protected.zip"}) {
		t.Fatal("expected archive support")
	}

	result, err := analyzer.Analyze(Input{Data: data, Name: "protected.zip"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Generic.Encrypted {
		t.Fatalf("expected encrypted evidence, got %+v", result.Generic)
	}
}

func TestArchiveAnalyzerUnreadableZip(t *testing.T) {
	data := []byte("PK\x03\x04 this is not a readable zip central directory")

	analyzer := NewArchiveAnalyzer()
	if !analyzer.Supports(Input{Data: data, Name: "broken.zip"}) {
		t.Fatal("expected archive support")
	}

	result, err := analyzer.Analyze(Input{Data: data, Name: "broken.zip"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Generic.Encrypted {
		t.Fatalf("expected encrypted/unreadable evidence, got %+v", result.Generic)
	}
}

func TestPDFAnalyzerEncrypted(t *testing.T) {
	pdf := []byte("%PDF-1.7\n1 0 obj<< /Encrypt 2 0 R >>endobj\ntrailer\n%%EOF")

	result, err := NewPDFAnalyzer().Analyze(Input{Data: pdf, Name: "locked.pdf"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Generic.Encrypted {
		t.Fatalf("expected encrypted evidence, got %+v", result.Generic)
	}
}

func TestGenericDetectsOLEEncryption(t *testing.T) {
	data := append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, []byte("EncryptedPackage\x00EncryptionInfo")...)

	generic := ScanGeneric(Input{Data: data, Name: "locked.docx"}, DefaultGenericOptions())
	if !generic.Encrypted {
		t.Fatalf("expected encrypted evidence, got %+v", generic)
	}
}

func TestEvidenceTextMentionsEncryption(t *testing.T) {
	ev := evidence.FileEvidence{
		StaticAnalysis: evidence.StaticAnalysis{
			Supported: true,
			Kind:      "archive",
			Generic:   evidence.GenericEvidence{Encrypted: true},
		},
	}

	if text := ev.ToText(false); !strings.Contains(text, "encrypted or password-protected") {
		t.Fatalf("expected encryption sentence in:\n%s", text)
	}
}

// markZipEncrypted sets the ZIP general-purpose "encrypted" flag in both the
// local file header and the central directory, without needing an encrypted
// binary fixture.
func markZipEncrypted(t *testing.T, data []byte) []byte {
	t.Helper()

	patched := append([]byte(nil), data...)
	count := 0

	for i := 0; i+10 < len(patched); i++ {
		if patched[i] == 'P' && patched[i+1] == 'K' && patched[i+2] == 0x03 && patched[i+3] == 0x04 {
			patched[i+6] |= 0x01
			count++
		}
		if patched[i] == 'P' && patched[i+1] == 'K' && patched[i+2] == 0x01 && patched[i+3] == 0x02 {
			patched[i+8] |= 0x01
			count++
		}
	}

	if count < 2 {
		t.Fatalf("expected local + central headers to patch, patched %d", count)
	}

	return patched
}

func TestGenericTextFile(t *testing.T) {
	analyzer := NewGenericAnalyzer()
	text := []byte("just a plain note with no links at all")

	if !analyzer.Supports(Input{Data: text, Name: "note.txt"}) {
		t.Fatal("expected text support")
	}

	result, err := analyzer.Analyze(Input{Data: text, Name: "note.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "text" {
		t.Fatalf("kind = %q", result.Kind)
	}
	if result.Generic.Empty() {
		t.Fatal("expected at least entropy/magic evidence")
	}
}

func TestEvidenceTextIncludesGeneric(t *testing.T) {
	ev := evidence.FileEvidence{
		StaticAnalysis: evidence.StaticAnalysis{
			Supported: true,
			Kind:      "pdf",
			Generic: evidence.GenericEvidence{
				HasJavaScript: true,
				AutoExec:      true,
				URLs:          []string{"http://evil.test/x"},
			},
		},
	}

	text := ev.ToText(false)
	for _, want := range []string{"PDF document", "JavaScript", "auto-execution", "URLs found: 1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in:\n%s", want, text)
		}
	}
}
