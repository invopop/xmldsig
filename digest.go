package xmldsig

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/xml"
)

// DigestXML will create a base64 encoded SHA512 hash of the struct passed as
// parameter (the struct should represent an XML)
func DigestXML(doc interface{}, namespaces Namespaces) (string, error) {
	data, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}

	return DigestBytes(data, namespaces)
}

// DigestBytes will create a base64 encoded SHA512 hash of the data passed as
// parameter
func DigestBytes(data []byte, ns Namespaces) (string, error) {
	out, err := Canonicalize(data, ns)
	if err != nil {
		return "", err
	}
	sum := sha512.Sum512(out)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
