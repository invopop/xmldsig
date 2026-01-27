package xmldsig_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"os"
	"testing"

	"github.com/beevik/etree"
	"github.com/invopop/xmldsig"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

// Full end to end test of signing flow - creates a signature and verifies that all hashes are correct
func TestKSeFSigning_InvoiceVat(t *testing.T) {
	verifyKSeFSigningFlow(t, "data/invoice-vat.xml")
}

func TestKSeFSigning_AuthRequest(t *testing.T) {
	verifyKSeFSigningFlow(t, "data/ksef-auth-request.xml")
}

func verifyKSeFSigningFlow(t *testing.T, xmlPath string) {
	// 1. Prepare a signed XML
	certificate, err := xmldsig.LoadCertificate("certs/cert-20260102-131809.pfx", "")
	require.NoError(t, err)

	originalXML, err := os.ReadFile(xmlPath)
	require.NoError(t, err)

	rootNamespaces := collectRootNamespaces(t, originalXML)

	signature, err := xmldsig.Sign(originalXML,
		xmldsig.WithCertificate(certificate),
		xmldsig.WithKSeF(),
	)
	require.NoError(t, err)

	signedXML := attachSignatureToDocument(t, originalXML, signature)

	// 2. Verify the hashes in the signature
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signedXML))

	signatureElement := findSignatureElement(doc.Root())
	require.NotNil(t, signatureElement, "signed XML does not contain a Signature element")

	signatureCopy := signatureElement.Copy()
	signatureElement.Parent().RemoveChild(signatureElement)

	unsignedDocBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	verifyDocumentReferenceDigest(t, unsignedDocBytes, signature)
	verifySignedPropertiesDigest(t, signatureCopy, signature)
	verifySignatureValue(t, signature, signatureCopy, certificate, rootNamespaces)
}

func attachSignatureToDocument(t *testing.T, docBytes []byte, signature *xmldsig.Signature) []byte {
	t.Helper()

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(docBytes))

	signatureBytes, err := xml.Marshal(signature)
	require.NoError(t, err)

	signatureDoc := etree.NewDocument()
	require.NoError(t, signatureDoc.ReadFromBytes(signatureBytes))

	doc.Root().AddChild(signatureDoc.Root())

	output, err := doc.WriteToBytes()
	require.NoError(t, err)

	return output
}

func verifyDocumentReferenceDigest(t *testing.T, unsignedDoc []byte, sig *xmldsig.Signature) {
	t.Helper()

	ref := findReference(sig.SignedInfo.Reference, func(r *xmldsig.Reference) bool {
		return r.Type == "http://www.w3.org/2000/09/xmldsig#Object"
	})
	require.NotNil(t, ref, "document reference not found in signature")

	canonicalizer := canonicalizerFromTransforms(t, ref.Transforms)
	canonicalized := canonicalizeBytes(t, unsignedDoc, canonicalizer)

	hash := hashFromAlgorithmURI(t, ref.DigestMethod.Algorithm)
	expectedDigest := ref.DigestValue
	actualDigest := computeDigestBase64(t, canonicalized, hash)

	require.Equal(t, expectedDigest, actualDigest, "document digest mismatch")
}

func verifySignedPropertiesDigest(t *testing.T, signatureElement *etree.Element, sig *xmldsig.Signature) {
	t.Helper()

	ref := findReference(sig.SignedInfo.Reference, func(r *xmldsig.Reference) bool {
		return r.Type == "http://uri.etsi.org/01903#SignedProperties"
	})
	require.NotNil(t, ref, "signed properties reference not found in signature")

	canonicalizer := canonicalizerFromTransforms(t, ref.Transforms)

	signedProps := signatureElement.FindElement(".//xades:SignedProperties")
	require.NotNil(t, signedProps, "SignedProperties element missing from signature")

	propsDoc := etree.NewDocument()
	propsDoc.SetRoot(signedProps.Copy())
	addNamespaces(propsDoc.Root(), xmldsig.Namespaces{
		"xades":      xmldsig.NamespaceXAdES,
		xmldsig.DSig: xmldsig.NamespaceDSig,
	})
	propsBytes, err := propsDoc.WriteToBytes()
	require.NoError(t, err)

	canonicalized := canonicalizeBytes(t, propsBytes, canonicalizer)
	hash := hashFromAlgorithmURI(t, ref.DigestMethod.Algorithm)
	expectedDigest := ref.DigestValue
	actualDigest := computeDigestBase64(t, canonicalized, hash)

	require.Equal(t, expectedDigest, actualDigest, "SignedProperties digest mismatch")
}

func verifySignatureValue(t *testing.T, sig *xmldsig.Signature, signatureElement *etree.Element, certificate *xmldsig.Certificate, rootNamespaces xmldsig.Namespaces) {
	t.Helper()

	require.NotNil(t, sig.SignedInfo.CanonicalizationMethod, "SignedInfo canonicalization method missing")
	require.NotNil(t, sig.SignedInfo.SignatureMethod, "SignedInfo signature method missing")

	canonicalizer := canonicalizerByAlgorithm(t, sig.SignedInfo.CanonicalizationMethod.Algorithm)

	signedInfoEl := signatureElement.FindElement(".//ds:SignedInfo")
	require.NotNil(t, signedInfoEl, "SignedInfo element not found in signature")

	signedInfoDoc := etree.NewDocument()
	signedInfoDoc.SetRoot(signedInfoEl.Copy())
	addNamespaces(signedInfoDoc.Root(), rootNamespacesWithDSig(rootNamespaces))
	signedInfoBytes, err := signedInfoDoc.WriteToBytes()
	require.NoError(t, err)

	canonicalized := canonicalizeBytes(t, signedInfoBytes, canonicalizer)

	hash := hashFromSignatureMethod(t, sig.SignedInfo.SignatureMethod.Algorithm)
	hasher := hash.New()
	_, err = hasher.Write(canonicalized)
	require.NoError(t, err)
	digest := hasher.Sum(nil)

	signatureValue, err := base64.StdEncoding.DecodeString(sig.Value.Value)
	require.NoError(t, err)

	publicKey := extractRSAPublicKey(t, certificate)
	err = rsa.VerifyPKCS1v15(publicKey, hash, digest, signatureValue)
	require.NoError(t, err, "SignatureValue does not match SignedInfo digest")
}

func canonicalizerFromTransforms(t *testing.T, transforms *xmldsig.Transforms) dsig.Canonicalizer {
	t.Helper()

	require.NotNil(t, transforms, "reference is missing transforms")

	for _, tr := range transforms.Transform {
		switch tr.Algorithm {
		case dsig.EnvelopedSignatureAltorithmId.String():
			continue
		case dsig.CanonicalXML10ExclusiveAlgorithmId.String():
			return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		case dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId.String():
			return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("")
		case dsig.CanonicalXML11AlgorithmId.String():
			return dsig.MakeC14N11Canonicalizer()
		case dsig.CanonicalXML11WithCommentsAlgorithmId.String():
			return dsig.MakeC14N11WithCommentsCanonicalizer()
		case dsig.CanonicalXML10RecAlgorithmId.String():
			return dsig.MakeC14N10RecCanonicalizer()
		case dsig.CanonicalXML10WithCommentsAlgorithmId.String():
			return dsig.MakeC14N10WithCommentsCanonicalizer()
		default:
			t.Fatalf("unsupported transform algorithm: %s", tr.Algorithm)
		}
	}

	t.Fatalf("no canonicalization transform found in reference")
	return nil
}

func canonicalizerByAlgorithm(t *testing.T, algorithm string) dsig.Canonicalizer {
	t.Helper()

	switch algorithm {
	case dsig.CanonicalXML10ExclusiveAlgorithmId.String():
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	case dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId.String():
		return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("")
	case dsig.CanonicalXML11AlgorithmId.String():
		return dsig.MakeC14N11Canonicalizer()
	case dsig.CanonicalXML11WithCommentsAlgorithmId.String():
		return dsig.MakeC14N11WithCommentsCanonicalizer()
	case dsig.CanonicalXML10RecAlgorithmId.String():
		return dsig.MakeC14N10RecCanonicalizer()
	case dsig.CanonicalXML10WithCommentsAlgorithmId.String():
		return dsig.MakeC14N10WithCommentsCanonicalizer()
	default:
		t.Fatalf("unsupported canonicalization algorithm: %s", algorithm)
		return nil
	}
}

func canonicalizeBytes(t *testing.T, data []byte, canonicalizer dsig.Canonicalizer) []byte {
	t.Helper()
	require.NotNil(t, canonicalizer, "canonicalizer must not be nil")

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(data))

	out, err := canonicalizer.Canonicalize(doc.Root())
	require.NoError(t, err)
	return out
}

func hashFromAlgorithmURI(t *testing.T, algorithm string) crypto.Hash {
	t.Helper()

	switch algorithm {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		return crypto.SHA1
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return crypto.SHA256
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		return crypto.SHA512
	default:
		t.Fatalf("unsupported digest algorithm: %s", algorithm)
		return 0
	}
}

func hashFromSignatureMethod(t *testing.T, algorithm string) crypto.Hash {
	t.Helper()

	switch algorithm {
	case xmldsig.AlgDSigRSASHA256:
		return crypto.SHA256
	case xmldsig.AlgDSigRSASHA512:
		return crypto.SHA512
	default:
		t.Fatalf("unsupported signature algorithm: %s", algorithm)
		return 0
	}
}

func computeDigestBase64(t *testing.T, data []byte, hash crypto.Hash) string {
	t.Helper()

	require.NotZero(t, hash, "hash algorithm is required")
	hasher := hash.New()
	_, err := hasher.Write(data)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

func extractRSAPublicKey(t *testing.T, certificate *xmldsig.Certificate) *rsa.PublicKey {
	t.Helper()

	block, _ := pem.Decode(certificate.PEM())
	require.NotNil(t, block, "failed to decode certificate PEM")

	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	pub, ok := parsed.PublicKey.(*rsa.PublicKey)
	require.True(t, ok, "certificate does not contain an RSA public key")
	return pub
}

func findReference(refs []*xmldsig.Reference, predicate func(*xmldsig.Reference) bool) *xmldsig.Reference {
	for _, ref := range refs {
		if predicate(ref) {
			return ref
		}
	}
	return nil
}

func findSignatureElement(el *etree.Element) *etree.Element {
	if el == nil {
		return nil
	}
	if el.Tag == "ds:Signature" || el.Tag == "Signature" {
		return el
	}
	for _, child := range el.ChildElements() {
		if found := findSignatureElement(child); found != nil {
			return found
		}
	}
	return nil
}

func collectRootNamespaces(t *testing.T, data []byte) xmldsig.Namespaces {
	t.Helper()

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(data))

	namespaces := make(xmldsig.Namespaces)
	for _, attr := range doc.Root().Attr {
		if attr.Space == "xmlns" {
			namespaces[attr.Key] = attr.Value
		}
		if attr.Space == "" && attr.Key == "xmlns" {
			namespaces[""] = attr.Value
		}
	}
	return namespaces
}

func rootNamespacesWithDSig(ns xmldsig.Namespaces) xmldsig.Namespaces {
	combined := cloneNamespaces(ns)
	if combined == nil {
		combined = make(xmldsig.Namespaces)
	}
	combined[xmldsig.DSig] = xmldsig.NamespaceDSig
	return combined
}

func cloneNamespaces(ns xmldsig.Namespaces) xmldsig.Namespaces {
	if ns == nil {
		return nil
	}
	c := make(xmldsig.Namespaces, len(ns))
	for k, v := range ns {
		c[k] = v
	}
	return c
}

func addNamespaces(el *etree.Element, namespaces xmldsig.Namespaces) {
	if el == nil || len(namespaces) == 0 {
		return
	}
	for prefix, uri := range namespaces {
		found := false
		for _, attr := range el.Attr {
			// Check for default namespace
			if prefix == "" {
				if attr.Space == "" && attr.Key == "xmlns" {
					found = true
					break
				}
			} else {
				if attr.Space == "xmlns" && attr.Key == prefix {
					found = true
					break
				}
			}
		}
		if !found {
			if prefix == "" {
				el.Attr = append(el.Attr, etree.Attr{
					Space: "",
					Key:   "xmlns",
					Value: uri,
				})
			} else {
				el.Attr = append(el.Attr, etree.Attr{
					Space: "xmlns",
					Key:   prefix,
					Value: uri,
				})
			}
		}
	}
}
