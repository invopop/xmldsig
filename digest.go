package xmldsig

import (
	"crypto"
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

// digest will create a base64 encoded hash of the struct passed as
// parameter (the struct should represent an XML).
func digest(doc interface{}, hash crypto.Hash, namespaces Namespaces) (string, error) {
	data, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}

	canonicalized, err := canonicalize(data, namespaces)
	if err != nil {
		return "", err
	}

	return digestBytes(canonicalized, hash)
}

// digestBytes will create a base64 encoded hash of the data passed as parameter.
func digestBytes(data []byte, hash crypto.Hash) (string, error) {
	if !hash.Available() {
		return "", fmt.Errorf("hash %v not available", hash)
	}

	hasher := hash.New()
	if _, err := hasher.Write(data); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}
