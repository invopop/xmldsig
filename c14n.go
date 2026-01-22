package xmldsig

import (
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// canonicalize will take the data and attempt to combine the namespaces provided.
// It doesn't do much more than that, as the golang xml lib already does most of the
// work of creating standard XML.

// Is it an exclusive or inclusive canonicalizer? It doesn't inspect parent elements, just the current element, but it can attach custom namespaces.
// But result of canonicalization is described as inclusive in the signed XML. This function is used to canonicalize SignedInfo, and for this element,
// it should be inclusive, as in SignedInfo there are references to other elements.

func canonicalize(data []byte, ns Namespaces) ([]byte, error) {
	return canonicalizeWith(data, ns, nil)
}

func canonicalizeWith(data []byte, ns Namespaces, canonicalizer dsig.Canonicalizer) ([]byte, error) {
	d := etree.NewDocument()
	d.Indent(etree.NoIndent)
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
		canonicalizer = dsig.MakeC14N10RecCanonicalizer()
	}
	return canonicalizer.Canonicalize(r)
}
