package xmldsig

import (
	"crypto"
	"fmt"
)

var signatureMethodURIs = map[crypto.Hash]string{
	crypto.SHA224:     AlgDSigRSASHA224,
	crypto.SHA256:     AlgDSigRSASHA256,
	crypto.SHA384:     AlgDSigRSASHA384,
	crypto.SHA512:     AlgDSigRSASHA512,
	crypto.SHA512_224: AlgDSigRSASHA512_224,
	crypto.SHA512_256: AlgDSigRSASHA512_256,
}

func signatureMethodURI(hash crypto.Hash) (string, error) {
	if uri, ok := signatureMethodURIs[hash]; ok {
		return uri, nil
	}
	return "", fmt.Errorf("unsupported signature method hash=%v", hash)
}
