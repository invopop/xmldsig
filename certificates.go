package xmldsig

import (
	"crypto"
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
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
	CaChain     []*x509.Certificate
	issuer      *pkix.RDNSequence
}

// PrivateKeyInfo contains info about modulus and exponent of the key
type PrivateKeyInfo struct {
	Modulus  string
	Exponent string
}

// Load creates a new Certificate from the info
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

	rsaPrivateKey := privateKey.(*rsa.PrivateKey)
	return &Certificate{
		privateKey:  rsaPrivateKey,
		certificate: certificate,
		CaChain:     caChain,
		issuer:      issuer,
	}, nil
}

// Sign will first create a hash of the data passed and then
// create a string (base64) representation of the signature obtained
// using the private key of the certificate
func (cert *Certificate) Sign(data string) (string, error) {
	hash := makeHash(data)

	signature, signingErr := rsa.SignPKCS1v15(rand.Reader, cert.privateKey, crypto.SHA256, hash)
	if signingErr != nil {
		return "", signingErr
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func makeHash(data string) []byte {
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(data))
	return hasher.Sum(nil)
}

// Fingerprint will return the SHA512 hash of the public key
func (cert *Certificate) Fingerprint() string {
	hasher := crypto.SHA512.New()
	hasher.Write(cert.certificate.Raw)
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// ToPEM will return the public certificate encoded in base64 PEM
// (without markers like "-----BEGIN CERTIFICATE-----")
func (cert *Certificate) NakedPEM() string {
	return NakedPEM(cert.certificate)
}

// PEM provides the PEM representation of the certificate.
func (cert *Certificate) PEM() []byte {
	return PEMCertificate(cert.certificate)
}

// PrivateKey provides the private key in PEM format.
func (cert *Certificate) PrivateKey() []byte {
	return PEMPrivateRSAKey(cert.privateKey)
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

// PrivateKeyInfo is the  RSA private key info
func (cert *Certificate) PrivateKeyInfo() *PrivateKeyInfo {
	exponentBytes := make([]byte, 3)
	exponentBytes[0] = byte(cert.privateKey.E >> 16)
	exponentBytes[1] = byte(cert.privateKey.E >> 8)
	exponentBytes[2] = byte(cert.privateKey.E)

	return &PrivateKeyInfo{
		Modulus:  base64.StdEncoding.EncodeToString(cert.privateKey.N.Bytes()),
		Exponent: base64.StdEncoding.EncodeToString(exponentBytes),
	}
}

// TLSConfig prepares TLS authentication connection details ready to use
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
