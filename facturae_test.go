package xmldsig

import "testing"

func TestFacturaeSignedSignaturePropertiesCustomElements(t *testing.T) {
	if facturaeSignedSignaturePropertiesCustomElements(nil) != nil {
		t.Fatalf("expected nil elements when config is nil")
	}

	cfg := &FacturaEConfig{
		Role: XAdESSignerRole("issuer"),
		Policy: &XAdESPolicyConfig{
			URL:         "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
			Description: "Política de Firma FacturaE v3.1",
			Algorithm:   "http://www.w3.org/2000/09/xmldsig#sha1",
			Hash:        "Ohixl6upD6av8N7pEvDABhEL6hM=",
		},
	}

	elements := facturaeSignedSignaturePropertiesCustomElements(cfg)
	if elements == nil {
		t.Fatalf("expected elements when config is provided")
	}

	if len(*elements) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(*elements))
	}

	policy := (*elements)[0]
	if policy.Space != "xades" || policy.Tag != "SignaturePolicyIdentifier" {
		t.Fatalf("unexpected policy element namespace/tag: %s:%s", policy.Space, policy.Tag)
	}

	sigPolicyID := policy.FindElement("xades:SignaturePolicyId/xades:SigPolicyId")
	if sigPolicyID == nil {
		t.Fatalf("missing SigPolicyId element")
	}
	identifier := sigPolicyID.SelectElement("xades:Identifier")
	if identifier == nil || identifier.Text() != cfg.Policy.URL {
		t.Fatalf("unexpected Identifier content: %v", identifier)
	}
	description := sigPolicyID.SelectElement("xades:Description")
	if description == nil || description.Text() != cfg.Policy.Description {
		t.Fatalf("unexpected Description content: %v", description)
	}
	sigPolicyHash := policy.FindElement("xades:SignaturePolicyId/xades:SigPolicyHash")
	if sigPolicyHash == nil {
		t.Fatalf("missing SigPolicyHash element")
	}
	digestMethod := sigPolicyHash.SelectElement("ds:DigestMethod")
	if digestMethod == nil {
		t.Fatalf("missing DigestMethod element")
	}
	if got := digestMethod.SelectAttrValue("Algorithm", ""); got != cfg.Policy.Algorithm {
		t.Fatalf("unexpected digest method algorithm: %s", got)
	}
	digestValue := sigPolicyHash.SelectElement("ds:DigestValue")
	if digestValue == nil || digestValue.Text() != cfg.Policy.Hash {
		t.Fatalf("unexpected digest value")
	}

	roleElement := (*elements)[1]
	if roleElement.Space != "xades" || roleElement.Tag != "SignerRole" {
		t.Fatalf("unexpected tag for role element: %s:%s", roleElement.Space, roleElement.Tag)
	}
	claimedRole := roleElement.FindElement("xades:ClaimedRoles/xades:ClaimedRole")
	if claimedRole == nil || claimedRole.Text() != cfg.Role.String() {
		t.Fatalf("unexpected claimed role content")
	}
}

func TestFacturaeSignedPropertiesCustomElements(t *testing.T) {
	if facturaeSignedPropertiesCustomElements(nil) != nil {
		t.Fatalf("expected nil elements when config is nil")
	}

	cfg := &FacturaEConfig{
		Description: "FacturaE data object",
	}

	elements := facturaeSignedPropertiesCustomElements(cfg)
	if elements == nil {
		t.Fatalf("expected elements when config is provided")
	}

	if len(*elements) != 1 {
		t.Fatalf("expected 1 element, got %d", len(*elements))
	}

	dataObject := (*elements)[0]
	if dataObject.Space != "xades" || dataObject.Tag != "DataObjectFormat" {
		t.Fatalf("unexpected tag for data object: %s:%s", dataObject.Space, dataObject.Tag)
	}

	objectRef := dataObject.SelectAttr("ObjectReference")
	if objectRef == nil {
		t.Fatalf("missing ObjectReference attribute")
	}
	if objectRef.Value != "#Reference" {
		t.Fatalf("unexpected ObjectReference value: %s", objectRef.Value)
	}

	description := dataObject.SelectElement("xades:Description")
	if description == nil || description.Text() != cfg.Description {
		t.Fatalf("unexpected description content")
	}

	identifier := dataObject.FindElement("xades:ObjectIdentifier/xades:Identifier")
	if identifier == nil {
		t.Fatalf("missing identifier element")
	}
	if got := identifier.SelectAttrValue("Qualifier", ""); got != "OIDAsURN" {
		t.Fatalf("unexpected identifier qualifier: %s", got)
	}
	if identifier.Text() != "urn:oid:1.2.840.10003.5.109.10" {
		t.Fatalf("unexpected identifier text: %s", identifier.Text())
	}

	mimeType := dataObject.SelectElement("xades:MimeType")
	if mimeType == nil || mimeType.Text() != "text/xml" {
		t.Fatalf("unexpected mime type content")
	}
}
