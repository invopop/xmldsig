package xmldsig

import (
	"encoding/xml"
	"testing"

	"github.com/beevik/etree"
)

func TestEtreeElementMarshalXML(t *testing.T) {
	root := etree.NewElement("xades:SignedProperties")
	root.CreateAttr("Id", "SignedProperties")
	root.CreateElement("xades:SigningTime").SetText("2024-01-01T00:00:00Z")

	type wrapper struct {
		Element *EtreeElement `xml:"xades:SignedProperties"`
	}

	data, err := xml.Marshal(wrapper{Element: NewEtreeElement(root)})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	expected := `<wrapper><xades:SignedProperties Id="SignedProperties"><xades:SigningTime>2024-01-01T00:00:00Z</xades:SigningTime></xades:SignedProperties></wrapper>`
	if string(data) != expected {
		t.Fatalf("unexpected marshaled XML:\nwant %s\n got %s", expected, data)
	}
}

func TestEtreeElementHelpers(t *testing.T) {
	root := etree.NewElement("xades:SignedProperties")
	root.CreateAttr("Id", "test-id")

	elem := NewEtreeElement(root)
	if elem == nil {
		t.Fatalf("expected non-nil wrapper")
	}
	if elem.Element() != root {
		t.Fatalf("Element() should return the wrapped pointer")
	}
	if elem.ID() != "test-id" {
		t.Fatalf("unexpected ID value: %s", elem.ID())
	}
}
