package analyzer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"slices"
	"testing"
	"time"
)

// sectionHeaderOffset is where minimalPE writes its only section header.
const sectionHeaderOffset = 0x80 + 4 + 20 + 224

func TestMatchSuspiciousUsesFunctionName(t *testing.T) {
	a := NewPEAnalyzer(0)
	got := a.matchSuspicious([]string{"WriteProcessMemory:KERNEL32.dll", "GetProcAddress:KERNEL32.dll", "CreateRemoteThread:KERNEL32.dll"})
	if !slices.Equal(got, []string{"CreateRemoteThread", "WriteProcessMemory"}) {
		t.Fatalf("matches = %v", got)
	}
}

func TestLargeVirtualSizeOnlyCountsForExecutableSections(t *testing.T) {
	a := NewPEAnalyzer(0)
	for _, tc := range []struct {
		characteristics uint32
		packed          bool
	}{
		{0xC0000040, false}, // initialized data, read/write: a normal .data/.bss
		{0x60000020, true},  // code, execute/read: unpack target
	} {
		image := minimalPE(".sect", make([]byte, 16), tc.characteristics)
		binary.LittleEndian.PutUint32(image[sectionHeaderOffset+8:], 0x10000) // VirtualSize

		result, err := a.Analyze(Input{Data: image})
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(result.PackerHints, "executable section much larger in memory than on disk"); got != tc.packed {
			t.Fatalf("characteristics %#x: hint = %v, hints %v", tc.characteristics, got, result.PackerHints)
		}
	}
}

func TestOpenPERecoversFromInvalidSymbolTable(t *testing.T) {
	image := minimalPE(".text", make([]byte, 64), 0x60000020)
	coff := 0x80 + 4
	binary.LittleEndian.PutUint32(image[coff+8:], uint32(len(image)+0x1000)) // PointerToSymbolTable past EOF
	binary.LittleEndian.PutUint32(image[coff+12:], 1)                        // NumberOfSymbols

	a := NewPEAnalyzer(0)
	if !a.Supports(Input{Data: image}) {
		t.Fatal("tampered symbol table must still be supported")
	}
	result, err := a.Analyze(Input{Data: image})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(result.PackerHints, "invalid COFF symbol table pointer") {
		t.Fatalf("hints = %v", result.PackerHints)
	}
}

func TestParseSignerPicksSignerCertificate(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Code Signing CA", Organization: []string{"Test CA Inc"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Example Publisher", Organization: []string{"Example Publisher"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	signer, ok := parseSigner(winCertificate(t, signedData(t, leaf, append(caDER, leafDER...))), nil, nil)
	if !ok {
		t.Fatal("expected signer")
	}
	if signer.Subject != "Example Publisher" || signer.Issuer != "Test Code Signing CA, Test CA Inc" {
		t.Fatalf("signer = %+v", signer)
	}

	if _, ok := parseSigner([]byte{1, 2, 3}, nil, nil); ok {
		t.Fatal("garbage must not yield a signer")
	}
}

func TestExtractURLsSkipsNamespaces(t *testing.T) {
	got := extractURLs([]byte(`xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings" http://evil.example/payload.bin`), 10)
	if !slices.Equal(got, []string{"http://evil.example/payload.bin"}) {
		t.Fatalf("urls = %v", got)
	}
}

// signedData builds a minimal PKCS#7 ContentInfo whose SignerInfo (with the
// trailing fields real signatures carry) points at signer.
func signedData(t *testing.T, signer *x509.Certificate, certs []byte) []byte {
	t.Helper()
	oidData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	type algorithm struct{ Algorithm asn1.ObjectIdentifier }
	signerInfo, err := asn1.Marshal(struct {
		Version               int
		IssuerAndSerialNumber struct {
			Issuer       asn1.RawValue
			SerialNumber *big.Int
		}
		DigestAlgorithm algorithm
		DigestEncAlg    algorithm
		Digest          []byte
	}{
		Version: 1,
		IssuerAndSerialNumber: struct {
			Issuer       asn1.RawValue
			SerialNumber *big.Int
		}{asn1.RawValue{FullBytes: signer.RawIssuer}, signer.SerialNumber},
		DigestAlgorithm: algorithm{oidSHA256},
		DigestEncAlg:    algorithm{oidSHA256},
		Digest:          []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatal(err)
	}

	inner, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      struct{ ContentType asn1.ObjectIdentifier }
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
		ContentInfo:      struct{ ContentType asn1.ObjectIdentifier }{oidData},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs},
		SignerInfos:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: signerInfo},
	})
	if err != nil {
		t.Fatal(err)
	}

	outer, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

func winCertificate(t *testing.T, pkcs7 []byte) []byte {
	t.Helper()
	table := make([]byte, 8, 8+len(pkcs7))
	binary.LittleEndian.PutUint32(table[0:], uint32(8+len(pkcs7)))
	binary.LittleEndian.PutUint16(table[4:], 0x0200) // WIN_CERT_REVISION_2_0
	binary.LittleEndian.PutUint16(table[6:], winCertTypePKCSSignedData)
	return append(table, pkcs7...)
}

func TestAuthenticodeVerification(t *testing.T) {
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Example Publisher"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &leafKey.PublicKey, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	image := minimalPE(".text", make([]byte, 64), 0x60000020)
	layout, ok := signatureLayout(image, false, len(image), 0)
	if !ok {
		t.Fatal("layout")
	}
	table := winCertificate(t, authenticodeSignedData(t, cert, leafKey, certDER, layout.fileDigest(image, crypto.SHA256)))
	certDir := layout.certDirOffset
	binary.LittleEndian.PutUint32(image[certDir:], uint32(len(image)))
	binary.LittleEndian.PutUint32(image[certDir+4:], uint32(len(table)))
	signedImage := append(image, table...)

	a := NewPEAnalyzer(0)
	result, err := a.Analyze(Input{Data: signedImage})
	if err != nil {
		t.Fatal(err)
	}
	if result.SignatureStatus != SignatureValid || !result.HasDigitalSignature || result.SignerSubject != "Example Publisher" {
		t.Fatalf("signed image: status=%q signed=%v signer=%q", result.SignatureStatus, result.HasDigitalSignature, result.SignerSubject)
	}

	tampered := bytes.Clone(signedImage)
	tampered[0x200] ^= 0xFF // first byte of .text
	result, err = a.Analyze(Input{Data: tampered})
	if err != nil {
		t.Fatal(err)
	}
	if result.SignatureStatus != SignatureInvalid || result.HasDigitalSignature {
		t.Fatalf("tampered image: status=%q signed=%v", result.SignatureStatus, result.HasDigitalSignature)
	}
}

// authenticodeSignedData builds a SignedData whose SpcIndirectDataContent
// carries fileDigest and whose authenticated attributes are signed by key.
func authenticodeSignedData(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey, certs []byte, fileDigest []byte) []byte {
	t.Helper()
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSpcIndirectData := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSHA256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	sha256Alg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	mustMarshal := func(value any) []byte {
		out, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	set := func(content []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: content}
	}

	spc := mustMarshal(struct {
		Data          struct{ Type asn1.ObjectIdentifier }
		MessageDigest struct {
			DigestAlgorithm pkix.AlgorithmIdentifier
			Digest          []byte
		}
	}{
		Data: struct{ Type asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}},
		MessageDigest: struct {
			DigestAlgorithm pkix.AlgorithmIdentifier
			Digest          []byte
		}{sha256Alg, fileDigest},
	})
	var spcRaw asn1.RawValue
	if _, err := asn1.Unmarshal(spc, &spcRaw); err != nil {
		t.Fatal(err)
	}
	spcDigest := sha256.Sum256(spcRaw.Bytes)

	attrs := mustMarshal(struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}{oidMessageDigest, set(mustMarshal(spcDigest[:]))})
	attrsDigest := sha256.Sum256(mustMarshal(set(attrs)))
	signature, err := ecdsa.SignASN1(rand.Reader, key, attrsDigest[:])
	if err != nil {
		t.Fatal(err)
	}

	signerInfo := mustMarshal(struct {
		Version               int
		IssuerAndSerialNumber struct {
			Issuer       asn1.RawValue
			SerialNumber *big.Int
		}
		DigestAlgorithm         pkix.AlgorithmIdentifier
		AuthenticatedAttributes asn1.RawValue
		DigestEncAlg            pkix.AlgorithmIdentifier
		Digest                  []byte
	}{
		Version: 1,
		IssuerAndSerialNumber: struct {
			Issuer       asn1.RawValue
			SerialNumber *big.Int
		}{asn1.RawValue{FullBytes: cert.RawIssuer}, cert.SerialNumber},
		DigestAlgorithm:         sha256Alg,
		AuthenticatedAttributes: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs},
		DigestEncAlg:            pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256},
		Digest:                  signature,
	})

	inner := mustMarshal(struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      struct {
			ContentType asn1.ObjectIdentifier
			Content     asn1.RawValue
		}
		Certificates asn1.RawValue
		SignerInfos  asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: set(mustMarshal(sha256Alg)),
		ContentInfo: struct {
			ContentType asn1.ObjectIdentifier
			Content     asn1.RawValue
		}{oidSpcIndirectData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: spc}},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs},
		SignerInfos:  set(signerInfo),
	})

	return mustMarshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
}
