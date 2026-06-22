package zatca

import (
	"fmt"
	"strings"

	"github.com/beevik/etree"
	"github.com/invopop/xmldsig"
)

// serializeDom4jSignedProperties produces a byte sequence equivalent to
// dom4j's asXML() output of an <xades:SignedProperties> element:
//   - xmlns:xades declared on the root element
//   - xmlns:ds declared on each ds:* descendant element individually
//   - self-closing for empty elements (etree default)
//   - original whitespace preserved
//
// It's the byte form ZATCA's fatoora validator digests. This lives in the
// ZATCA profile (rather than the core library) because it is a ZATCA-specific
// deviation, injected into signing via XAdESConfig.SignedPropertiesSerializer.
//
// Why this exists instead of standard canonicalization: ZATCA does NOT
// canonicalize SignedProperties before hashing it; it hashes dom4j's asXML()
// output directly. That output differs from C14N in three independent ways,
// none of which is a configurable option in a C14N canonicalizer:
//
//  1. Namespaces: dom4j redeclares xmlns:ds on every ds:* element, whereas
//     C14N declares it once on the nearest ancestor and lets it inherit.
//  2. Empty elements: dom4j keeps them self-closing (<ds:DigestMethod/>),
//     whereas canonical XML mandates expanded start+end tags
//     (<ds:DigestMethod></ds:DigestMethod>).
//  3. Root declarations: C14N hoists xmlns:ds onto the root and sorts the
//     namespace declarations; dom4j leaves only xmlns:xades there.
//
// Because no canonicalizer can reproduce these bytes, we must replicate dom4j's
// serialization here to match the digest the validator computes.
func serializeDom4jSignedProperties(spBytes []byte) ([]byte, error) {
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
		if a.Space == xmldsig.XMLNS || (a.Space == "" && a.Key == xmldsig.XMLNS) {
			continue
		}
		filtered = append(filtered, a)
	}
	spCopy.Attr = filtered

	spCopy.Attr = append([]etree.Attr{{
		Space: xmldsig.XMLNS,
		Key:   xmldsig.XAdES,
		Value: xmldsig.NamespaceXAdES,
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
		if child.Space == xmldsig.DSig {
			found := false
			for _, a := range child.Attr {
				if a.Space == xmldsig.XMLNS && a.Key == xmldsig.DSig {
					found = true
					break
				}
			}
			if !found {
				child.Attr = append([]etree.Attr{{
					Space: xmldsig.XMLNS,
					Key:   xmldsig.DSig,
					Value: xmldsig.NamespaceDSig,
				}}, child.Attr...)
			}
		}
		addDsNamespace(child)
	}
}
