package xmldsig

import (
	"sort"
	"strings"

	"github.com/beevik/etree"
)

// Canonicalize will take the data and attempt to combine the namespaces provided.
// It doesn't do much more than that, as the golang xml lib already does most of the
// work of creating standard XML.
func Canonicalize(data []byte, ns Namespaces) ([]byte, error) {
	d := etree.NewDocument()
	d.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: true,
		CanonicalText:    true,
		CanonicalAttrVal: true,
	}
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
	sort.Sort(byCanonicalAttr(r.Attr))

	return d.WriteToBytes()
}

type byCanonicalAttr []etree.Attr

func (a byCanonicalAttr) Len() int {
	return len(a)
}

func (a byCanonicalAttr) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a byCanonicalAttr) Less(i, j int) bool {
	// we have two sets of attrs to sort, first those with the "xmlns" space,
	// then everything else.

	// First deal with default namespace which must always come first
	if a[i].Key == XMLNS {
		// Always first!
		return true
	}
	if a[j].Key == XMLNS {
		return false
	}

	// Next deal with the namespaces
	if a[i].Space == XMLNS && (a[j].Space != XMLNS) {
		return true
	}
	if a[j].Key == XMLNS || (a[i].Space != XMLNS && a[j].Space == XMLNS) {
		return false
	}

	// Spaces are ordered by their values, not names! (seriously WTF!)
	is := a[i].Space
	js := a[j].Space
	for _, v := range a {
		if v.Space == XMLNS {
			if v.Key == a[i].Space {
				is = v.Value
			}
			if v.Key == a[j].Space {
				js = v.Value
			}
		}
	}

	sp := strings.Compare(is, js)
	if sp == 0 {
		return strings.Compare(a[i].Key, a[j].Key) < 0
	}
	return sp < 0
}
