package analyzer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1" // Authenticode digests
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"strings"
)

const winCertTypePKCSSignedData = 0x0002

// Signature integrity, as stored in evidence.StaticAnalysis.SignatureStatus.
// "valid" means the file digest matches the signed digest and the signer
// certificate's key signed it. The certificate chain is NOT validated, so a
// valid signature proves integrity, not that the publisher is trustworthy.
const (
	SignatureValid      = "valid"
	SignatureInvalid    = "invalid"
	SignatureUnverified = "unverified"
)

var (
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	digestHashes     = map[string]crypto.Hash{
		"1.3.14.3.2.26":          crypto.SHA1,
		"2.16.840.1.101.3.4.2.1": crypto.SHA256,
		"2.16.840.1.101.3.4.2.2": crypto.SHA384,
		"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	}
)

// Signer describes the Authenticode signing certificate and whether the
// signature matches the file.
type Signer struct {
	Subject string
	Issuer  string
	Status  string
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue     `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue     `asn1:"optional,tag:1"`
	SignerInfos      []pkcs7SignerInfo `asn1:"set"`
}

type pkcs7SignerInfo struct {
	Version               int
	IssuerAndSerialNumber struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
}

type spcIndirectDataContent struct {
	Data          asn1.RawValue
	MessageDigest struct {
		DigestAlgorithm pkix.AlgorithmIdentifier
		Digest          []byte
	}
}

type pkcs7Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// peSignatureLayout locates the regions Authenticode leaves out of the file
// digest: the optional header checksum, the security directory entry and the
// certificate table itself.
type peSignatureLayout struct {
	checksumOffset int
	certDirOffset  int
	tableOffset    int
	tableSize      int
}

// certificateTable returns the WIN_CERTIFICATE blob located by the security
// data directory (whose VirtualAddress is a file offset, not an RVA).
func certificateTable(data []byte, offset, size uint32) ([]byte, bool) {
	start, end := uint64(offset), uint64(offset)+uint64(size)
	if offset == 0 || size < 8 || end > uint64(len(data)) {
		return nil, false
	}
	return data[start:end], true
}

// signatureLayout computes the excluded regions for a PE image whose
// certificate table starts at tableOffset.
func signatureLayout(data []byte, pe32Plus bool, tableOffset, tableSize int) (peSignatureLayout, bool) {
	if len(data) < 0x40 {
		return peSignatureLayout{}, false
	}
	optional := int(binary.LittleEndian.Uint32(data[0x3C:])) + 4 + 20
	directories := optional + 96
	if pe32Plus {
		directories = optional + 112
	}
	layout := peSignatureLayout{
		checksumOffset: optional + 64,
		certDirOffset:  directories + 4*8,
		tableOffset:    tableOffset,
		tableSize:      tableSize,
	}
	if optional < 0x40 || layout.certDirOffset+8 > tableOffset {
		return peSignatureLayout{}, false
	}
	return layout, true
}

// fileDigest hashes the image the way Authenticode does in practice: the
// whole file in order, minus the checksum, the security directory entry and
// the certificate table.
func (l peSignatureLayout) fileDigest(data []byte, hash crypto.Hash) []byte {
	h := hash.New()
	h.Write(data[:l.checksumOffset])
	h.Write(data[l.checksumOffset+4 : l.certDirOffset])
	h.Write(data[l.certDirOffset+8 : l.tableOffset])
	h.Write(data[l.tableOffset+l.tableSize:])
	return h.Sum(nil)
}

// parseSigner extracts the signer certificate's names from a WIN_CERTIFICATE
// blob holding PKCS#7 SignedData and, when the image layout is known, checks
// that the signature matches the file.
func parseSigner(table []byte, data []byte, layout *peSignatureLayout) (Signer, bool) {
	if len(table) < 8 {
		return Signer{}, false
	}
	length := binary.LittleEndian.Uint32(table[0:4])
	if binary.LittleEndian.Uint16(table[6:8]) != winCertTypePKCSSignedData || length < 8 || int(length) > len(table) {
		return Signer{}, false
	}

	var content pkcs7ContentInfo
	if _, err := asn1.Unmarshal(table[8:length], &content); err != nil {
		return Signer{}, false
	}
	var signed pkcs7SignedData
	if _, err := asn1.Unmarshal(content.Content.Bytes, &signed); err != nil {
		return Signer{}, false
	}

	// Certificates are parsed one by one so a single malformed certificate in
	// the chain does not hide the signer.
	var certs []*x509.Certificate
	for rest := signed.Certificates.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		next, err := asn1.Unmarshal(rest, &raw)
		if err != nil {
			break
		}
		if cert, err := x509.ParseCertificate(raw.FullBytes); err == nil {
			certs = append(certs, cert)
		}
		rest = next
	}
	if len(certs) == 0 {
		return Signer{}, false
	}

	signerCert := certs[0]
	var info *pkcs7SignerInfo
	if len(signed.SignerInfos) > 0 {
		info = &signed.SignerInfos[0]
		serial := info.IssuerAndSerialNumber.SerialNumber
		for _, cert := range certs {
			if serial != nil && cert.SerialNumber.Cmp(serial) == 0 && bytes.Equal(cert.RawIssuer, info.IssuerAndSerialNumber.Issuer.FullBytes) {
				signerCert = cert
				break
			}
		}
	}

	signer := Signer{
		Subject: displayName(signerCert.Subject),
		Issuer:  displayName(signerCert.Issuer),
		Status:  SignatureUnverified,
	}
	if info != nil && layout != nil {
		signer.Status = verifySignature(signed.ContentInfo, info, signerCert, data, *layout)
	}
	return signer, true
}

// verifySignature checks the three links of an Authenticode signature:
// file digest == SpcIndirectDataContent digest, hash(SpcIndirectDataContent)
// == signed messageDigest attribute, and the attributes are signed by the
// signer certificate's key.
func verifySignature(contentInfo asn1.RawValue, info *pkcs7SignerInfo, cert *x509.Certificate, data []byte, layout peSignatureLayout) string {
	var inner pkcs7ContentInfo
	if _, err := asn1.Unmarshal(contentInfo.FullBytes, &inner); err != nil {
		return SignatureUnverified
	}
	var spc spcIndirectDataContent
	if _, err := asn1.Unmarshal(inner.Content.Bytes, &spc); err != nil {
		return SignatureUnverified
	}

	fileHash, ok := digestHashes[spc.MessageDigest.DigestAlgorithm.Algorithm.String()]
	if !ok || !fileHash.Available() {
		return SignatureUnverified
	}
	if !bytes.Equal(layout.fileDigest(data, fileHash), spc.MessageDigest.Digest) {
		return SignatureInvalid
	}

	signerHash, ok := digestHashes[info.DigestAlgorithm.Algorithm.String()]
	if !ok || !signerHash.Available() || len(info.AuthenticatedAttributes.Bytes) == 0 {
		return SignatureUnverified
	}

	// The messageDigest covers the SpcIndirectDataContent contents octets,
	// without the outer SEQUENCE tag and length.
	var spcRaw asn1.RawValue
	if _, err := asn1.Unmarshal(inner.Content.Bytes, &spcRaw); err != nil {
		return SignatureUnverified
	}
	h := signerHash.New()
	h.Write(spcRaw.Bytes)
	if digest, ok := messageDigestAttribute(info.AuthenticatedAttributes.Bytes); !ok || !bytes.Equal(digest, h.Sum(nil)) {
		return SignatureInvalid
	}

	// The signature covers the attributes re-encoded as a SET, not as [0].
	signedAttrs, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: info.AuthenticatedAttributes.Bytes})
	if err != nil {
		return SignatureUnverified
	}
	h = signerHash.New()
	h.Write(signedAttrs)
	attrsDigest := h.Sum(nil)

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(key, signerHash, attrsDigest, info.EncryptedDigest) != nil {
			return SignatureInvalid
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, attrsDigest, info.EncryptedDigest) {
			return SignatureInvalid
		}
	default:
		return SignatureUnverified
	}
	return SignatureValid
}

func messageDigestAttribute(attributes []byte) ([]byte, bool) {
	for rest := attributes; len(rest) > 0; {
		var attr pkcs7Attribute
		next, err := asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil, false
		}
		if attr.Type.Equal(oidMessageDigest) {
			var digest []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &digest); err != nil {
				return nil, false
			}
			return digest, true
		}
		rest = next
	}
	return nil, false
}

func displayName(name pkix.Name) string {
	parts := []string{}
	if name.CommonName != "" {
		parts = append(parts, name.CommonName)
	}
	if len(name.Organization) > 0 && name.Organization[0] != name.CommonName {
		parts = append(parts, name.Organization[0])
	}
	return strings.Join(parts, ", ")
}
