package xmldsig

import (
	"crypto"
	"fmt"
)

var signatureMethodURIs = map[crypto.Hash]string{
	crypto.SHA256: AlgDSigRSASHA256,
	crypto.SHA512: AlgDSigRSASHA512,
}

func signatureMethodURI(hash crypto.Hash) (string, error) {
	if uri, ok := signatureMethodURIs[hash]; ok {
		return uri, nil
	}
	return "", fmt.Errorf("unsupported signature method hash=%v", hash)
}
