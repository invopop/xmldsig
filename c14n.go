package xmldsig

import (
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// serializeDom4jStyle re-serializes XML to match dom4j's asXML() behavior:
//   - xmlns:xades declared on the root element
//   - xmlns:ds repeated on EACH ds:* child element (not inherited)
//   - self-closing for empty elements (etree default)
//   - original whitespace preserved
//
// This is needed because ZATCA's validator extracts the SignedProperties
// element using dom4j and hashes its asXML() output.
func serializeDom4jStyle(data []byte) ([]byte, error) {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(data); err != nil {
		return nil, err
	}
	r := d.Root()

	// Remove all xmlns:* declarations from the root — we'll re-add selectively.
	filtered := make([]etree.Attr, 0, len(r.Attr))
	for _, a := range r.Attr {
		if a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns") {
			continue
		}
		filtered = append(filtered, a)
	}
	r.Attr = filtered

	// Add xmlns:xades on the root element (dom4j adds ns of the extracted node).
	r.Attr = append([]etree.Attr{{
		Space: "xmlns",
		Key:   "xades",
		Value: NamespaceXAdES,
	}}, r.Attr...)

	// Walk all descendants: add xmlns:ds on each ds:* element.
	addDsNamespaceToChildren(r)

	return d.WriteToBytes()
}

// addDsNamespaceToChildren recursively adds xmlns:ds to every element
// that uses the "ds" namespace prefix, matching dom4j's asXML() behavior.
func addDsNamespaceToChildren(el *etree.Element) {
	for _, child := range el.ChildElements() {
		if child.Space == "ds" {
			// Check if xmlns:ds is already present
			found := false
			for _, a := range child.Attr {
				if a.Space == "xmlns" && a.Key == "ds" {
					found = true
					break
				}
			}
			if !found {
				child.Attr = append([]etree.Attr{{
					Space: "xmlns",
					Key:   "ds",
					Value: NamespaceDSig,
				}}, child.Attr...)
			}
		}
		addDsNamespaceToChildren(child)
	}
}

// canonicalizeWith combines the namespaces provided and canonicalizes the data using the selected canonicalizer.
func canonicalizeWith(data []byte, ns Namespaces, canonicalizer dsig.Canonicalizer) ([]byte, error) {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(data); err != nil {
		return nil, err
	}
	r := d.Root()

	// Add any missing namespaces
	for _, v := range ns.defs() {
		match := false
		for _, a := range r.Attr {
			if a.Space == v.Space && a.Key == v.Key {
				match = true
			}
		}
		if !match {
			r.Attr = append(r.Attr, v)
		}
	}

	if canonicalizer == nil {
		return nil, fmt.Errorf("canonicalizer must not be nil")
	}
	return canonicalizer.Canonicalize(r)
}
