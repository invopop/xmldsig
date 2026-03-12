package xmldsig

import (
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

func TestCanonicalizeKeepsXMLWhenAlreadyCanonical(t *testing.T) {
	const xmlInput = `<Root attr="value"><Child>text</Child></Root>`

	got, err := canonicalizeWith([]byte(xmlInput), nil, dsig.MakeC14N10RecCanonicalizer())
	if err != nil {
		t.Fatalf("canonicalize returned error: %v", err)
	}

	if string(got) != xmlInput {
		t.Fatalf("canonicalize mismatch\nwant: %q\n got: %q", xmlInput, string(got))
	}
}

func TestCanonicalizeAddsMissingNamespaces(t *testing.T) {
	const xmlInput = `<Invoice xmlns="urn:example:invoice"></Invoice>`
	ns := Namespaces{
		"c11n": "urn:custom",
		DSig:   NamespaceDSig,
		XAdES:  NamespaceXAdES,
	}

	got, err := canonicalizeWith([]byte(xmlInput), ns, dsig.MakeC14N10RecCanonicalizer())
	if err != nil {
		t.Fatalf("canonicalize returned error: %v", err)
	}

	const want = `<Invoice xmlns="urn:example:invoice" xmlns:c11n="urn:custom" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"></Invoice>`
	if string(got) != want {
		t.Fatalf("canonicalize mismatch\nwant: %q\n got: %q", want, string(got))
	}
}

func TestCanonicalizeOrdersAttributesByNamespace(t *testing.T) {
	const xmlInput = `<Invoice xmlns:beta="http://beta.example.com" xmlns:alpha="http://alpha.example.com" beta:Id="b" alpha:Id="a" plain="p"></Invoice>`

	got, err := canonicalizeWith([]byte(xmlInput), nil, dsig.MakeC14N10RecCanonicalizer())
	if err != nil {
		t.Fatalf("canonicalize returned error: %v", err)
	}

	const want = `<Invoice xmlns:alpha="http://alpha.example.com" xmlns:beta="http://beta.example.com" plain="p" alpha:Id="a" beta:Id="b"></Invoice>`
	if string(got) != want {
		t.Fatalf("canonicalize mismatch\nwant: %q\n got: %q", want, string(got))
	}
}

func TestCanonicalizeNormalizesWhitespaceAndEmptyElements(t *testing.T) {
	const xmlInput = `<Root>
    <Data attr="line1
line2"/>
    <Content> value </Content>
</Root>`

	got, err := canonicalizeWith([]byte(xmlInput), nil, dsig.MakeC14N10RecCanonicalizer())
	if err != nil {
		t.Fatalf("canonicalize returned error: %v", err)
	}

	const want = `<Root>
    <Data attr="line1&#xA;line2"></Data>
    <Content> value </Content>
</Root>`
	if string(got) != want {
		t.Fatalf("canonicalize mismatch\nwant: %q\n got: %q", want, string(got))
	}
}

func TestCanonicalizeHandlesUnusedAncestorNamespaces(t *testing.T) {
	const xmlInput = `<Element>content</Element>`
	ns := Namespaces{
		"ns1": "urn:unused",
	}

	t.Run("Inclusive keeps unused namespaces", func(t *testing.T) {
		got, err := canonicalizeWith([]byte(xmlInput), ns, dsig.MakeC14N10RecCanonicalizer())
		if err != nil {
			t.Fatalf("canonicalize error: %v", err)
		}

		// Unused namespace should be present because it's from ancestor context
		// and Inclusive C14N 1.0 preserves it.
		const want = `<Element xmlns:ns1="urn:unused">content</Element>`
		if string(got) != want {
			t.Errorf("want %q, got %q", want, string(got))
		}
	})

	t.Run("Exclusive removes unused namespaces", func(t *testing.T) {
		got, err := canonicalizeWith([]byte(xmlInput), ns, dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""))
		if err != nil {
			t.Fatalf("canonicalize error: %v", err)
		}

		// Unused namespace should be removed by Exclusive C14N
		const want = `<Element>content</Element>`
		if string(got) != want {
			t.Errorf("want %q, got %q", want, string(got))
		}
	})
}
