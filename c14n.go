package xmldsig

import (
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

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
