package xmldsig

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// ErrNotFound is returned when a matching certificate was not found.
var ErrNotFound = errors.New("not found")

// Certificate stores information about a signing Certificate
// which can be used to sign a facturae XML
type Certificate struct {
	privateKey  crypto.Signer
	certificate *x509.Certificate
	CaChain     []*x509.Certificate
	issuer      *pkix.RDNSequence
}

// KeyAlgorithm describes the public key algorithm exposed via PrivateKeyInfo.
type KeyAlgorithm string

const (
	KeyAlgorithmUnknown KeyAlgorithm = ""
	KeyAlgorithmRSA     KeyAlgorithm = "RSA"
	KeyAlgorithmECDSA   KeyAlgorithm = "ECDSA"
)

// PrivateKeyInfo contains public information extracted from the private key.
// Values are base64-encoded to match XML-DSig expectations when embedding
// ds:KeyInfo payloads.
type PrivateKeyInfo struct {
	Algorithm KeyAlgorithm

	// RSA fields
	Modulus  string
	Exponent string

	// ECDSA fields
	CurveURI  string
	PublicKey string
}

// NewCertificate creates a Certificate from a parsed x509.Certificate and
// a crypto.Signer
func NewCertificate(cert *x509.Certificate, key crypto.Signer) (*Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if key == nil {
		return nil, fmt.Errorf("private key is required")
	}
	issuer := &pkix.RDNSequence{}
	if _, err := asn1.Unmarshal(cert.RawIssuer, issuer); err != nil {
		return nil, fmt.Errorf("parsing issuer: %w", err)
	}
	return &Certificate{
		privateKey:  key,
		certificate: cert,
		issuer:      issuer,
	}, nil
}

// LoadCertificate creates a new Certificate instance from a PKCS12 file
// at the given path with the given password
func LoadCertificate(path, password string) (*Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}
	return LoadCertificateFromBytes(data, password)
}

// LoadCertificateFromBytes creates a new Certificate instance from a PKCS12
// certificate given as bytes, with the given password
func LoadCertificateFromBytes(data []byte, password string) (*Certificate, error) {
	privateKey, certificate, caChain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, err
	}

	issuer := &pkix.RDNSequence{}
	_, err = asn1.Unmarshal(certificate.RawIssuer, issuer)
	if err != nil {
		return nil, err
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type")
	}
	return &Certificate{
		privateKey:  signer,
		certificate: certificate,
		CaChain:     caChain,
		issuer:      issuer,
	}, nil
}

// Sign hashes the provided data with the requested hash algorithm and signs the
// digest using the configured private key. For ECDSA keys, ecdsaFormat controls
// whether the signature is returned in concatenated r||s format (W3C XML DSig
// standard) or raw DER encoding (required by ZATCA).
func (cert *Certificate) Sign(data string, hash crypto.Hash, ecdsaFormatDER bool) (string, error) {
	if hash == 0 {
		hash = crypto.SHA256
	}
	if !hash.Available() {
		return "", fmt.Errorf("hash %v not available", hash)
	}

	hasher := hash.New()
	if _, err := hasher.Write([]byte(data)); err != nil {
		return "", err
	}
	digest := hasher.Sum(nil)

	signature, err := cert.privateKey.Sign(rand.Reader, digest, hash)
	if err != nil {
		return "", err
	}

	// ECDSA signers return a DER-encoded signature. The W3C XML DSig standard
	// requires the concatenated r||s form, so convert it unless the caller
	// explicitly wants the raw DER encoding (required by ZATCA).
	if cert.PublicKeyAlgorithm() == x509.ECDSA && !ecdsaFormatDER {
		signature, err = derToConcatenatedECDSA(signature, cert.privateKey.Public())
		if err != nil {
			return "", err
		}
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

// derToConcatenatedECDSA converts a DER-encoded ECDSA signature into the
// concatenated format (r || s) required by XML DSig. The curve size is derived
// from the public key so it works for any crypto.Signer implementation.
func derToConcatenatedECDSA(derSig []byte, pub crypto.PublicKey) ([]byte, error) {
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ecdsa public key, got %T", pub)
	}

	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, err
	}

	keyBytes := (ecdsaPub.Curve.Params().BitSize + 7) / 8
	rBytes := sig.R.FillBytes(make([]byte, keyBytes))
	sBytes := sig.S.FillBytes(make([]byte, keyBytes))
	signature := append(rBytes, sBytes...)

	return signature, nil
}

// Fingerprint returns the requested hash of the certificate's DER bytes.
func (cert *Certificate) Fingerprint(hash crypto.Hash) (string, error) {
	if hash == 0 {
		hash = crypto.SHA512
	}
	if !hash.Available() {
		return "", fmt.Errorf("hash %v not available", hash)
	}
	hasher := hash.New()
	if _, err := hasher.Write(cert.certificate.Raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// FingerprintPEM returns the hash of the certificate's base64 PEM text
// (without headers), hex-encoded and then base64-encoded: base64(hex(hash)).
func (cert *Certificate) FingerprintPEM(hash crypto.Hash) (string, error) {
	return digestBytesHex([]byte(cert.NakedPEM()), hash)
}

// NakedPEM will return the public certificate encoded in base64 PEM
// (without markers like "-----BEGIN CERTIFICATE-----")
func (cert *Certificate) NakedPEM() string {
	return NakedPEM(cert.certificate)
}

// PEM provides the PEM representation of the certificate.
func (cert *Certificate) PEM() []byte {
	return PEMCertificate(cert.certificate)
}

// PrivateKey provides the private key in PEM format for both RSA and ECDSA keys.
func (cert *Certificate) PrivateKey() []byte {
	switch key := cert.privateKey.(type) {
	case *rsa.PrivateKey:
		return PEMPrivateRSAKey(key)
	case *ecdsa.PrivateKey:
		return PEMPrivateECDSAKey(key)
	default:
		return nil
	}
}

// NakedPEM converts a x509 formated certificate to the PEM format without
// the headers, useful for including in the XML document.
func NakedPEM(cert *x509.Certificate) string {
	replacer := strings.NewReplacer(
		"-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "")
	pem := string(PEMCertificate(cert))
	return replacer.Replace(pem)
}

// PEMCertificate provides the complete PEM version of the certificate.
func PEMCertificate(cert *x509.Certificate) []byte {
	pemBlock := pem.Block{
		Type:    "CERTIFICATE",
		Headers: map[string]string{},
		Bytes:   cert.Raw,
	}
	return pem.EncodeToMemory(&pemBlock)
}

// PEMPrivateRSAKey issues a PEM string with the RSA Key.
func PEMPrivateRSAKey(key *rsa.PrivateKey) []byte {
	pb := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(pb)
}

// PEMPrivateECDSAKey issues a PEM string with the ECDSA Key.
func PEMPrivateECDSAKey(key *ecdsa.PrivateKey) []byte {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil
	}
	pb := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	return pem.EncodeToMemory(pb)
}

// Issuer returns a description of the certificate issuer
func (cert *Certificate) Issuer() string {
	return cert.issuer.String()
}

// SerialNumber returns the serial number of the certificate
func (cert *Certificate) SerialNumber() string {
	return cert.certificate.SerialNumber.String()
}

// SubjectSerialNumber returns the serialNumber attribute from the
// certificate's Subject Distinguished Name (OID 2.5.4.5). This is
// typically used to carry national identifiers such as "TINPL-…",
// "PNOPL-…", "PESEL-…", or "NIP-…" in Polish qualified certificates.
func (cert *Certificate) SubjectSerialNumber() string {
	return cert.certificate.Subject.SerialNumber
}

// PublicKeyAlgorithm exposes the public key algorithm of the certificate.
func (cert *Certificate) PublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	return cert.certificate.PublicKeyAlgorithm
}

// PrivateKeyInfo exposes public components of the configured private key that
// may be embedded in ds:KeyInfo blocks for interoperability.
func (cert *Certificate) PrivateKeyInfo() *PrivateKeyInfo {
	switch privateKey := cert.privateKey.(type) {
	case *rsa.PrivateKey:
		exponentBytes := make([]byte, 3)
		exponentBytes[0] = byte(privateKey.E >> 16)
		exponentBytes[1] = byte(privateKey.E >> 8)
		exponentBytes[2] = byte(privateKey.E)

		return &PrivateKeyInfo{
			Algorithm: KeyAlgorithmRSA,
			Modulus:   base64.StdEncoding.EncodeToString(privateKey.N.Bytes()),
			Exponent:  base64.StdEncoding.EncodeToString(exponentBytes),
		}
	case *ecdsa.PrivateKey:
		curveEntry, ok := curveMap[privateKey.Curve.Params().Name]
		if !ok {
			return nil
		}
		// ecdsa.PrivateKey and ecdh.PrivateKey are not compatible, so we need to convert one to another
		ecdhPrivateKey, err := curveEntry.curve.NewPrivateKey(privateKey.D.Bytes())
		if err != nil {
			return nil
		}
		ecdhPublicKey := ecdhPrivateKey.PublicKey()
		return &PrivateKeyInfo{
			Algorithm: KeyAlgorithmECDSA,
			CurveURI:  curveEntry.uri,
			PublicKey: base64.StdEncoding.EncodeToString(ecdhPublicKey.Bytes()),
		}
	}

	return nil
}

var curveMap = map[string]struct {
	uri   string
	curve ecdh.Curve
}{
	"P-256": {"urn:oid:1.2.840.10045.3.1.7", ecdh.P256()},
	"P-384": {"urn:oid:1.3.132.0.34", ecdh.P384()},
	"P-521": {"urn:oid:1.3.132.0.35", ecdh.P521()},
}

// TLSAuthConfig prepares TLS authentication connection details ready to use
// with HTTP servers that require them in addition to the signatures of the
// XML-DSig signed payload.
func (cert *Certificate) TLSAuthConfig() (*tls.Config, error) {
	// Build tls.Certificate directly using the crypto.Signer interface
	// This works for both RSA and ECDSA keys
	pair := tls.Certificate{
		Certificate: [][]byte{cert.certificate.Raw},
		PrivateKey:  cert.privateKey,
		Leaf:        cert.certificate,
	}

	rootCAs := x509.NewCertPool()
	for _, c := range cert.CaChain {
		rootCAs.AddCert(c)
	}
	return &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{pair},
	}, nil
}
