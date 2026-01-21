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

	return digestBytes(data, hash, namespaces)
}

// digestBytes will create a base64 encoded hash of the data passed as parameter.
func digestBytes(data []byte, hash crypto.Hash, ns Namespaces) (string, error) {
	if !hash.Available() {
		return "", fmt.Errorf("hash %v not available", hash)
	}

	out, err := canonicalize(data, ns)
	if err != nil {
		return "", err
	}

	hasher := hash.New()
	if _, err := hasher.Write(out); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}
