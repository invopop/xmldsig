package xmldsig

import (
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// SerializeDom4jSignedProperties produces a byte sequence equivalent to
// dom4j's asXML() output of an <xades:SignedProperties> element:
//   - xmlns:xades declared on the root element
//   - xmlns:ds declared on each ds:* descendant element individually
//   - self-closing for empty elements (etree default)
//   - original whitespace preserved
//
// It's the byte form ZATCA's fatoora validator (and any other validator
// hashing SP via dom4j) digests.
func SerializeDom4jSignedProperties(spBytes []byte) ([]byte, error) {
	doc := etree.NewDocument()
	doc.ReadSettings.PreserveCData = true
	if err := doc.ReadFromBytes(spBytes); err != nil {
		return nil, fmt.Errorf("parse SignedProperties: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("SignedProperties has no root element")
	}
	out, err := serializeDom4jStyle(root)
	if err != nil {
		return nil, fmt.Errorf("dom4j serialize SignedProperties: %w", err)
	}
	return []byte(out), nil
}

func serializeDom4jStyle(sp *etree.Element) (string, error) {
	spCopy := sp.Copy()

	filtered := make([]etree.Attr, 0, len(spCopy.Attr))
	for _, a := range spCopy.Attr {
		if a.Space == XMLNS || (a.Space == "" && a.Key == XMLNS) {
			continue
		}
		filtered = append(filtered, a)
	}
	spCopy.Attr = filtered

	spCopy.Attr = append([]etree.Attr{{
		Space: XMLNS,
		Key:   XAdES,
		Value: NamespaceXAdES,
	}}, spCopy.Attr...)

	addDsNamespace(spCopy)

	d := etree.NewDocument()
	d.SetRoot(spCopy)
	out, err := d.WriteToBytes()
	if err != nil {
		return "", err
	}

	s := string(out)
	if strings.HasPrefix(s, "<?xml") {
		if idx := strings.Index(s, "?>"); idx >= 0 {
			s = s[idx+2:]
			if len(s) > 0 && s[0] == '\n' {
				s = s[1:]
			}
		}
	}

	return s, nil
}

func addDsNamespace(el *etree.Element) {
	for _, child := range el.ChildElements() {
		if child.Space == DSig {
			found := false
			for _, a := range child.Attr {
				if a.Space == XMLNS && a.Key == DSig {
					found = true
					break
				}
			}
			if !found {
				child.Attr = append([]etree.Attr{{
					Space: XMLNS,
					Key:   DSig,
					Value: NamespaceDSig,
				}}, child.Attr...)
			}
		}
		addDsNamespace(child)
	}
}
