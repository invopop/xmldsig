package xmldsig

import (
	"crypto"
	"fmt"
)

var hashAlgorithmURIs = map[crypto.Hash]string{
	crypto.SHA224:     "http://www.w3.org/2001/04/xmlenc#sha224",
	crypto.SHA256:     "http://www.w3.org/2001/04/xmlenc#sha256",
	crypto.SHA384:     "http://www.w3.org/2001/04/xmlenc#sha384",
	crypto.SHA512:     "http://www.w3.org/2001/04/xmlenc#sha512",
	crypto.SHA512_224: "http://www.w3.org/2001/04/xmlenc#sha512/224",
	crypto.SHA512_256: "http://www.w3.org/2001/04/xmlenc#sha512/256",
}

func hashAlgorithmURI(hash crypto.Hash) (string, error) {
	if uri, ok := hashAlgorithmURIs[hash]; ok {
		return uri, nil
	}
	return "", fmt.Errorf("unsupported hash algorithm %v", hash)
}
