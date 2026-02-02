package xmldsig

import (
	"encoding/xml"
	"errors"
	"fmt"
)

// Object wraps the XAdES qualifying properties
type Object struct {
	QualifyingProperties *QualifyingProperties `xml:"xades:QualifyingProperties"`
}

// QualifyingProperties contains XAdES-specific signature data. XAdES-specific namespace is required, so we use `xades` prefix.
type QualifyingProperties struct {
	XAdESNamespace string `xml:"xmlns:xades,attr,omitempty"`
	ID             string `xml:"Id,attr"`
	Target         string `xml:"Target,attr"`

	SignedProperties   *SignedProperties   `xml:"xades:SignedProperties"`
	UnsignedProperties *UnsignedProperties `xml:"xades:UnsignedProperties,omitempty"`
}

// SignedProperties represents the root xades:SignedProperties element.
type SignedProperties struct {
	XMLName                    xml.Name                    `xml:"xades:SignedProperties"`
	ID                         string                      `xml:"Id,attr"`
	SignedSignatureProperties  *SignedSignatureProperties  `xml:"xades:SignedSignatureProperties"`
	SignedDataObjectProperties *SignedDataObjectProperties `xml:"xades:SignedDataObjectProperties,omitempty"`
}

// SignedSignatureProperties contains signer-specific statements such as SigningTime and SigningCertificate.
type SignedSignatureProperties struct {
	SigningTime               string                     `xml:"xades:SigningTime"`
	SigningCertificate        *SigningCertificate        `xml:"xades:SigningCertificate"`
	SignaturePolicyIdentifier *SignaturePolicyIdentifier `xml:"xades:SignaturePolicyIdentifier,omitempty"`
	SignerRole                *SignerRole                `xml:"xades:SignerRole,omitempty"`
}

// SigningCertificate encloses certificate details required by XAdES.
type SigningCertificate struct {
	Cert *Cert `xml:"xades:Cert"`
}

// Cert encapsulates digest and issuer information for the signing certificate.
type Cert struct {
	CertDigest   *CertDigest   `xml:"xades:CertDigest"`
	IssuerSerial *IssuerSerial `xml:"xades:IssuerSerial"`
}

// CertDigest contains the digest method and value for the signing certificate.
type CertDigest struct {
	DigestMethod *AlgorithmMethod `xml:"ds:DigestMethod"`
	DigestValue  string           `xml:"ds:DigestValue"`
}

// IssuerSerial wraps issuer and serial number statements for a certificate.
type IssuerSerial struct {
	X509IssuerName   string `xml:"ds:X509IssuerName"`
	X509SerialNumber string `xml:"ds:X509SerialNumber"`
}

// SignaturePolicyIdentifier links to the policy governing the signature process.
type SignaturePolicyIdentifier struct {
	SignaturePolicyID *SignaturePolicyID `xml:"xades:SignaturePolicyId"`
}

// SignaturePolicyID contains the identifier and optional hash of the policy.
type SignaturePolicyID struct {
	SigPolicyID   *SigPolicyID   `xml:"xades:SigPolicyId"`
	SigPolicyHash *SigPolicyHash `xml:"xades:SigPolicyHash,omitempty"`
}

// SigPolicyID holds the identifier and optional description of the policy.
type SigPolicyID struct {
	Identifier  Identifier `xml:"xades:Identifier"`
	Description string     `xml:"xades:Description,omitempty"`
}

// SigPolicyHash carries the digest of the linked signature policy.
type SigPolicyHash struct {
	DigestMethod *AlgorithmMethod `xml:"ds:DigestMethod,omitempty"`
	DigestValue  string           `xml:"ds:DigestValue,omitempty"`
}

// SignerRole enumerates claimed signer roles.
type SignerRole struct {
	ClaimedRoles *ClaimedRoles `xml:"xades:ClaimedRoles"`
}

// ClaimedRoles holds one or more claimed role declarations.
type ClaimedRoles struct {
	ClaimedRole []string `xml:"xades:ClaimedRole"`
}

// SignedDataObjectProperties describes signed objects such as the main document body.
type SignedDataObjectProperties struct {
	DataObjectFormat *DataObjectFormat `xml:"xades:DataObjectFormat"`
}

func (s *Signature) buildSignedPropertiesElement() (*SignedProperties, error) {
	if s.opts.xadesOptions == nil {
		return nil, errors.New("missing xades options")
	}
	cert := s.opts.cert
	if cert == nil {
		return nil, errors.New("missing certificate")
	}
	certHash := s.opts.xadesOptions.SigningCertificateHash
	fingerprint, err := cert.Fingerprint(certHash)
	if err != nil {
		return nil, fmt.Errorf("certificate fingerprint: %w", err)
	}
	certDigestAlgorithm, err := hashAlgorithmURI(certHash)
	if err != nil {
		return nil, fmt.Errorf("certificate digest algorithm: %w", err)
	}

	signingCertificate := &SigningCertificate{
		Cert: &Cert{
			CertDigest: &CertDigest{
				DigestMethod: &AlgorithmMethod{Algorithm: certDigestAlgorithm},
				DigestValue:  fingerprint,
			},
			IssuerSerial: &IssuerSerial{
				X509IssuerName:   s.serializeIssuer(cert),
				X509SerialNumber: cert.SerialNumber(),
			},
		},
	}

	signedSignatureProps := &SignedSignatureProperties{
		SigningTime:        s.opts.xadesOptions.TimestampFormatter(s.opts.timeNow()),
		SigningCertificate: signingCertificate,
		SignerRole:         buildSignerRole(s.opts.xadesOptions.Role),
		SignaturePolicyIdentifier: buildSignaturePolicyIdentifier(
			s.opts.xadesOptions.PolicyIdentifier,
		),
	}

	signedProps := &SignedProperties{
		ID:                        fmt.Sprintf(sigPropertiesIDFormat, s.opts.docID),
		SignedSignatureProperties: signedSignatureProps,
		SignedDataObjectProperties: buildSignedDataObjectProperties(
			s.opts.xadesOptions.DataObjectFormat,
			fmt.Sprintf(signedDataReferenceID, s.opts.docID),
		),
	}

	return signedProps, nil
}

func (s *Signature) serializeIssuer(cert *Certificate) string {
	if s.opts.xadesOptions != nil {
		if serializer := s.opts.xadesOptions.IssuerSerializer; serializer != nil && cert.issuer != nil {
			return serializer(*cert.issuer)
		}
	}
	return cert.Issuer()
}

func buildSignerRole(roles *[]string) *SignerRole {
	if roles == nil {
		return nil
	}
	roleValues := make([]string, 0, len(*roles))
	for _, r := range *roles {
		if r == "" {
			continue
		}
		roleValues = append(roleValues, r)
	}
	if len(roleValues) == 0 {
		return nil
	}
	return &SignerRole{
		ClaimedRoles: &ClaimedRoles{
			ClaimedRole: roleValues,
		},
	}
}

func buildSignaturePolicyIdentifier(policy *PolicyIdentifier) *SignaturePolicyIdentifier {
	if policy == nil || policy.Identifier.Value == "" {
		return nil
	}
	identifier := &SignaturePolicyIdentifier{
		SignaturePolicyID: &SignaturePolicyID{
			SigPolicyID: &SigPolicyID{
				Identifier:  policy.Identifier,
				Description: policy.Description,
			},
		},
	}
	if policy.DigestMethodAlgorithm != "" || policy.DigestValue != "" {
		identifier.SignaturePolicyID.SigPolicyHash = &SigPolicyHash{
			DigestValue: policy.DigestValue,
		}
		if policy.DigestMethodAlgorithm != "" {
			identifier.SignaturePolicyID.SigPolicyHash.DigestMethod = &AlgorithmMethod{
				Algorithm: policy.DigestMethodAlgorithm,
			}
		}
	}
	return identifier
}

func buildSignedDataObjectProperties(format *DataObjectFormat, referenceID string) *SignedDataObjectProperties {
	if format == nil {
		return nil
	}
	clone := *format
	if clone.ObjectReference == "" {
		clone.ObjectReference = "#" + referenceID
	}
	return &SignedDataObjectProperties{
		DataObjectFormat: &clone,
	}
}
