package xmldsig

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

// Supported signing algorithms URIs.
const (
	AlgDSigRSASHA224     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
	AlgDSigRSASHA256     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgDSigRSASHA384     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgDSigRSASHA512     = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgDSigRSASHA512_224 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512/224"
	AlgDSigRSASHA512_256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512/256"
	AlgDSigECDSASHA224   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
	AlgDSigECDSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	AlgDSigECDSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	AlgDSigECDSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

var signatureMethodURIs = map[x509.PublicKeyAlgorithm]map[crypto.Hash]string{
	x509.RSA: {
		crypto.SHA224:     AlgDSigRSASHA224,
		crypto.SHA256:     AlgDSigRSASHA256,
		crypto.SHA384:     AlgDSigRSASHA384,
		crypto.SHA512:     AlgDSigRSASHA512,
		crypto.SHA512_224: AlgDSigRSASHA512_224,
		crypto.SHA512_256: AlgDSigRSASHA512_256,
	},
	x509.ECDSA: {
		crypto.SHA224: AlgDSigECDSASHA224,
		crypto.SHA256: AlgDSigECDSASHA256,
		crypto.SHA384: AlgDSigECDSASHA384,
		crypto.SHA512: AlgDSigECDSASHA512,
	},
}

func signatureMethodURI(hash crypto.Hash, keyAlgorithm x509.PublicKeyAlgorithm) (string, error) {
	algorithms, ok := signatureMethodURIs[keyAlgorithm]
	if !ok {
		return "", fmt.Errorf("unsupported signature key algorithm=%v", keyAlgorithm)
	}
	if uri, ok := algorithms[hash]; ok {
		return uri, nil
	}
	return "", fmt.Errorf("unsupported signature method hash=%v keyAlgorithm=%v", hash, keyAlgorithm)
}
