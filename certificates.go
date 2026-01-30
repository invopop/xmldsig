package xmldsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// LoadCertificate creates a new Certificate instance from the info
// obtained from pkcs12 formated data stream
func LoadCertificate(path, password string) (*Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

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
// digest using the configured private key.
func (cert *Certificate) Sign(data string, hash crypto.Hash) (string, error) {
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

	signature, signingErr := cert.privateKey.Sign(rand.Reader, digest, hash)
	if signingErr != nil {
		return "", signingErr
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Fingerprint returns the requested hash of the certificate bytes.
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

// NakedPEM will return the public certificate encoded in base64 PEM
// (without markers like "-----BEGIN CERTIFICATE-----")
func (cert *Certificate) NakedPEM() string {
	return NakedPEM(cert.certificate)
}

// PEM provides the PEM representation of the certificate.
func (cert *Certificate) PEM() []byte {
	return PEMCertificate(cert.certificate)
}

// PrivateKey provides the private key in PEM format, if it's a RSA key.
func (cert *Certificate) PrivateKey() []byte {
	privateKey, ok := cert.privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil
	}
	return PEMPrivateRSAKey(privateKey)
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

// Issuer returns a description of the certificate issuer
func (cert *Certificate) Issuer() string {
	return cert.issuer.String()
}

// SerialNumber returns the serial number of the certificate
func (cert *Certificate) SerialNumber() string {
	return cert.certificate.SerialNumber.String()
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
		curveURI := namedCurveURI(privateKey.Curve)
		if curveURI == "" {
			return nil
		}
		publicKey := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
		return &PrivateKeyInfo{
			Algorithm: KeyAlgorithmECDSA,
			CurveURI:  curveURI,
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		}
	}

	return nil
}

func namedCurveURI(curve elliptic.Curve) string {
	if curve == nil {
		return ""
	}
	params := curve.Params()
	if params == nil {
		return ""
	}
	switch params.Name {
	case "P-224":
		return "urn:oid:1.3.132.0.33"
	case "P-256":
		return "urn:oid:1.2.840.10045.3.1.7"
	case "P-384":
		return "urn:oid:1.3.132.0.34"
	case "P-521":
		return "urn:oid:1.3.132.0.35"
	default:
		return ""
	}
}

// TLSAuthConfig prepares TLS authentication connection details ready to use
// with HTTP servers that require them in addition to the signatures of the
// XML-DSig signed payload.
func (cert *Certificate) TLSAuthConfig() (*tls.Config, error) {
	pair, err := tls.X509KeyPair(cert.PEM(), cert.PrivateKey())
	if err != nil {
		return nil, err
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
