package xmldsig

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/xml"
)

// digest will create a base64 encoded SHA512 hash of the struct passed as
// parameter (the struct should represent an XML)
func digest(doc interface{}, namespaces Namespaces) (string, error) {
	data, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}

	return digestBytes(data, namespaces)
}

// digestBytes will create a base64 encoded SHA512 hash of the data passed as
// parameter
func digestBytes(data []byte, ns Namespaces) (string, error) {
	out, err := canonicalize(data, ns)
	if err != nil {
		return "", err
	}
	sum := sha512.Sum512(out)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
