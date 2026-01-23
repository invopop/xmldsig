package xmldsig

import (
	"encoding/xml"

	"github.com/beevik/etree"
)

// EtreeElement wraps an etree.Element so it can be marshaled by encoding/xml.
type EtreeElement struct {
	element *etree.Element
}

// NewEtreeElement wraps the provided element, returning nil when el is nil.
func NewEtreeElement(el *etree.Element) *EtreeElement {
	if el == nil {
		return nil
	}
	return &EtreeElement{element: el}
}

// Element exposes the underlying etree element for inspection.
func (e *EtreeElement) Element() *etree.Element {
	if e == nil {
		return nil
	}
	return e.element
}

// ID returns the value of the Id attribute on the wrapped element.
func (e *EtreeElement) ID() string {
	if e == nil || e.element == nil {
		return ""
	}
	return e.element.SelectAttrValue("Id", "")
}

// MarshalXML implements xml.Marshaler so the wrapped etree element is emitted directly.
func (e *EtreeElement) MarshalXML(enc *xml.Encoder, _ xml.StartElement) error {
	if e == nil || e.element == nil {
		return nil
	}
	if err := encodeElement(enc, e.element); err != nil {
		return err
	}
	return enc.Flush()
}

func encodeElement(enc *xml.Encoder, el *etree.Element) error {
	if el == nil {
		return nil
	}
	start := xml.StartElement{Name: elementName(el.Space, el.Tag)}
	for _, attr := range el.Attr {
		start.Attr = append(start.Attr, xml.Attr{
			Name:  elementName(attr.Space, attr.Key),
			Value: attr.Value,
		})
	}
	if err := enc.EncodeToken(start); err != nil {
		return err
	}
	for _, child := range el.Child {
		switch c := child.(type) {
		case *etree.Element:
			if err := encodeElement(enc, c); err != nil {
				return err
			}
		case *etree.CharData:
			if err := enc.EncodeToken(xml.CharData([]byte(c.Data))); err != nil {
				return err
			}
		case *etree.Comment:
			if err := enc.EncodeToken(xml.Comment([]byte(c.Data))); err != nil {
				return err
			}
		case *etree.Directive:
			if err := enc.EncodeToken(xml.Directive([]byte(c.Data))); err != nil {
				return err
			}
		case *etree.ProcInst:
			if err := enc.EncodeToken(xml.ProcInst{
				Target: c.Target,
				Inst:   []byte(c.Inst),
			}); err != nil {
				return err
			}
		}
	}
	return enc.EncodeToken(start.End())
}

func elementName(space, tag string) xml.Name {
	if space == "" {
		return xml.Name{Local: tag}
	}
	return xml.Name{Local: space + ":" + tag}
}
