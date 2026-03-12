package xmldsig

import (
	"crypto"
	"encoding/base64"
	"fmt"
)

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
