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

	// RSA and ECDSA certificates require different signing code
	// (even though both implement crypto.Signer)
	var signature []byte
	var signingErr error
	switch cert.privateKey.(type) {
	case *rsa.PrivateKey:
		signature, signingErr = cert.privateKey.Sign(rand.Reader, digest, hash)
	case *ecdsa.PrivateKey:
		// When using ECDSA, privateKey.Sign returns signature in DER format, but XML DSig
		// requires the signature to be in the concatenated format (r || s)
		signature, signingErr = signECDSA(cert.privateKey.(*ecdsa.PrivateKey), digest, hash)
	default:
		return "", fmt.Errorf("unsupported key type: %T", cert.privateKey)
	}

	if signingErr != nil {
		return "", signingErr
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

// signECDSA creates a signature for the provided digest using the private key,
// and returns it in the concatenated format (r || s) required by XML DSig
func signECDSA(privateKey *ecdsa.PrivateKey, digest []byte, hash crypto.Hash) ([]byte, error) {
	derSig, err := privateKey.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, err
	}

	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, err
	}

	keyBytes := (privateKey.Curve.Params().BitSize + 7) / 8
	rBytes := sig.R.FillBytes(make([]byte, keyBytes))
	sBytes := sig.S.FillBytes(make([]byte, keyBytes))
	signature := append(rBytes, sBytes...)

	return signature, nil
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
