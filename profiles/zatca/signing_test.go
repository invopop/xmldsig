package zatca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/invopop/xmldsig"
	"github.com/invopop/xmldsig/profiles/zatca"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

// compactInvoice is a single-line UBL invoice that still carries the three
// elements ZATCA's XPath transforms exclude from the invoice hash.
const compactInvoice = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" ` +
	`xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" ` +
	`xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" ` +
	`xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">` +
	`<ext:UBLExtensions><ext:UBLExtension><ext:ExtensionURI>urn:test</ext:ExtensionURI></ext:UBLExtension></ext:UBLExtensions>` +
	`<cbc:ProfileID>reporting:1.0</cbc:ProfileID>` +
	`<cbc:ID>SME00010</cbc:ID>` +
	`<cbc:IssueDate>2024-01-01</cbc:IssueDate>` +
	`<cbc:InvoiceTypeCode name="0200000">388</cbc:InvoiceTypeCode>` +
	`<cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID><cbc:UUID>10</cbc:UUID></cac:AdditionalDocumentReference>` +
	`<cac:AdditionalDocumentReference><cbc:ID>QR</cbc:ID><cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">AQ==</cbc:EmbeddedDocumentBinaryObject></cac:Attachment></cac:AdditionalDocumentReference>` +
	`<cac:Signature><cbc:ID>urn:oasis:names:specification:ubl:signature:Invoice</cbc:ID></cac:Signature>` +
	`<cac:AccountingSupplierParty><cac:Party><cbc:Name>Test Supplier</cbc:Name></cac:Party></cac:AccountingSupplierParty>` +
	`<cac:LegalMonetaryTotal><cbc:PayableAmount currencyID="SAR">115.00</cbc:PayableAmount></cac:LegalMonetaryTotal>` +
	`</Invoice>`

func TestSignCompactInvoice(t *testing.T) {
	key, cert := newTestCertificate(t)
	unsigned := stripHashExcludedElements(t, compactInvoice)
	require.NotContains(t, string(unsigned), "\n", "fixture must stay compact")

	sig, err := xmldsig.Sign(unsigned,
		xmldsig.WithCertificate(cert),
		xmldsig.WithXMLDSigConfig(zatca.XMLDSigConfig()),
		xmldsig.WithXAdESConfig(zatca.XAdESConfig()),
	)
	require.NoError(t, err)
	docRef := sig.SignedInfo.Reference[0]

	t.Run("document digest is the SHA-256 of the C14N11 compact invoice", func(t *testing.T) {
		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(unsigned))
		canonical, err := dsig.MakeC14N11Canonicalizer().Canonicalize(doc.Root())
		require.NoError(t, err)
		require.NotContains(t, string(canonical), "\n")

		expected := sha256.Sum256(canonical)
		require.Equal(t, base64.StdEncoding.EncodeToString(expected[:]), docRef.DigestValue)
	})

	t.Run("signature value is ECDSA-SHA256 over the raw document digest", func(t *testing.T) {
		digest, err := base64.StdEncoding.DecodeString(docRef.DigestValue)
		require.NoError(t, err)
		require.Len(t, digest, sha256.Size)

		signatureValue, err := base64.StdEncoding.DecodeString(sig.Value.Value)
		require.NoError(t, err)

		hashed := sha256.Sum256(digest)
		require.True(t, ecdsa.VerifyASN1(&key.PublicKey, hashed[:], signatureValue),
			"SignatureValue does not verify over the raw document digest")
	})
}

// newTestCertificate returns a throwaway P-256 key and a self-signed certificate for it.
func newTestCertificate(t *testing.T) (*ecdsa.PrivateKey, *xmldsig.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zatca-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	cert, err := xmldsig.NewCertificate(parsed, key)
	require.NoError(t, err)
	return key, cert
}

// stripHashExcludedElements removes UBLExtensions, cac:Signature and the QR
// AdditionalDocumentReference, mirroring the profile's XPath document transforms.
func stripHashExcludedElements(t *testing.T, invoice string) []byte {
	t.Helper()

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(invoice))
	root := doc.Root()
	for _, el := range root.ChildElements() {
		switch el.Tag {
		case "UBLExtensions", "Signature":
			root.RemoveChild(el)
		case "AdditionalDocumentReference":
			if id := el.SelectElement("ID"); id != nil && strings.TrimSpace(id.Text()) == "QR" {
				root.RemoveChild(el)
			}
		}
	}
	out, err := doc.WriteToBytes()
	require.NoError(t, err)
	return out
}
