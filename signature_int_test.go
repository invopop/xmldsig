package xmldsig

import (
	"sort"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSortAttrs(t *testing.T) {
	d := etree.NewDocument()
	d.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: true,
		CanonicalText:    true,
		CanonicalAttrVal: true,
	}
	d.Indent(etree.NoIndent)
	// data taken from official example at https://www.w3.org/TR/2001/REC-xml-c14n-20010315
	data := `<e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
	xmlns:b="http://www.ietf.org"
	xmlns:a="http://www.w3.org"
	xmlns="http://example.org"/>`
	require.NoError(t, d.ReadFromString(data))

	e := d.Root()
	sort.Sort(byCanonicalAttr(e.Attr))

	out, err := d.WriteToString()
	assert.NoError(t, err)
	assert.Equal(t, `<e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>`, out)
}
