package xmldsig

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/xml"
	"errors"
	"fmt"
)

// Object wraps the XAdES qualifying properties
type Object struct {
	QualifyingProperties *QualifyingProperties `xml:"xades:QualifyingProperties"`
}

// XAdESSignerRole defines the accepted signer roles for XAdES signatures.
type XAdESSignerRole string

// String converts the XAdES role into a string.
func (r XAdESSignerRole) String() string {
	return string(r)
}

// XAdESPolicyConfig provides a convenient way to specify what policy details to add to the XAdES signature.
type XAdESPolicyConfig struct {
	URL         string `json:"url"`                    // URL to the policy definition; also used as SPURI qualifier when Identifier is set
	Identifier  string `json:"identifier,omitempty"`   // OID/URN identifier (when set, used as the policy identifier instead of URL)
	Description string `json:"description,omitempty"`  // Optional human description
	Algorithm   string `json:"algorithm"`              // eg. SHA1 or SHA256
	Hash        string `json:"hash"`                   // Base64 encoded hash (usually provided with policy)
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
	SigningTime               string              `xml:"xades:SigningTime"`
	SigningCertificate        *SigningCertificate `xml:"xades:SigningCertificate"`
	SignaturePolicyIdentifier *PolicyIdentifier   `xml:"xades:SignaturePolicyIdentifier,omitempty"`
	SignerRole                *SignerRole         `xml:"xades:SignerRole,omitempty"`
}

// SigningCertificate encloses certificate details required by XAdES.
type SigningCertificate struct {
	Cert []*Cert `xml:"xades:Cert"`
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

// DataObjectFormat describes the xades:DataObjectFormat element.
type DataObjectFormat struct {
	ObjectReference  string            `xml:"ObjectReference,attr"`
	Description      string            `xml:"xades:Description,omitempty"`
	ObjectIdentifier *ObjectIdentifier `xml:"xades:ObjectIdentifier,omitempty"`
	MimeType         string            `xml:"xades:MimeType,omitempty"`
	Encoding         string            `xml:"xades:Encoding,omitempty"`
}

// ObjectIdentifier configures xades:ObjectIdentifier element content.
type ObjectIdentifier struct {
	Identifier  Identifier `xml:"xades:Identifier"`
	Description string     `xml:"xades:Description,omitempty"`
}

// Identifier is reused by multiple elements to represent string content with an optional qualifier attribute.
type Identifier struct {
	Qualifier string `xml:"Qualifier,attr,omitempty"`
	Value     string `xml:",chardata"`
}

// PolicyIdentifier represents xades:SignaturePolicyIdentifier > xades:SignaturePolicyId.
type PolicyIdentifier struct {
	SignaturePolicyID *PolicySignaturePolicyID `xml:"xades:SignaturePolicyId"`
}

// PolicySignaturePolicyID contains the policy identifier and optional hash data.
type PolicySignaturePolicyID struct {
	SigPolicyID         PolicySigPolicyID    `xml:"xades:SigPolicyId"`
	SigPolicyHash       *PolicySigPolicyHash `xml:"xades:SigPolicyHash,omitempty"`
	SigPolicyQualifiers *SigPolicyQualifiers `xml:"xades:SigPolicyQualifiers,omitempty"`
}

// SigPolicyQualifiers holds policy qualifier elements such as SPURI.
type SigPolicyQualifiers struct {
	SigPolicyQualifier []SigPolicyQualifier `xml:"xades:SigPolicyQualifier"`
}

// SigPolicyQualifier contains a single policy qualifier (e.g. SPURI).
type SigPolicyQualifier struct {
	SPURI string `xml:"xades:SPURI"`
}

// PolicySigPolicyID wraps identifier and description fields.
type PolicySigPolicyID struct {
	Identifier  Identifier `xml:"xades:Identifier"`
	Description string     `xml:"xades:Description,omitempty"`
}

// PolicySigPolicyHash carries information about the policy hash.
type PolicySigPolicyHash struct {
	DigestMethod *AlgorithmMethod `xml:"ds:DigestMethod,omitempty"`
	DigestValue  string           `xml:"ds:DigestValue,omitempty"`
}

func (s *Signature) buildSignedPropertiesElement() (*SignedProperties, error) {
	if s.opts.xadesConfig == nil {
		return nil, errors.New("missing xades options")
	}
	cert := s.opts.cert
	if cert == nil {
		return nil, errors.New("missing certificate")
	}
	certHash := s.opts.xadesConfig.SigningCertificateHash
	fingerprint, err := cert.Fingerprint(certHash)
	if err != nil {
		return nil, fmt.Errorf("certificate fingerprint: %w", err)
	}
	certDigestAlgorithm, err := hashAlgorithmURI(certHash)
	if err != nil {
		return nil, fmt.Errorf("certificate digest algorithm: %w", err)
	}

	signingCertificate := &SigningCertificate{
		Cert: []*Cert{
			{
				CertDigest: &CertDigest{
					DigestMethod: &AlgorithmMethod{Algorithm: certDigestAlgorithm},
					DigestValue:  fingerprint,
				},
				IssuerSerial: &IssuerSerial{
					X509IssuerName:   s.serializeIssuer(cert),
					X509SerialNumber: cert.SerialNumber(),
				},
			},
		},
	}

	if s.opts.xadesConfig.IncludeCaChain {
		for _, ca := range cert.CaChain {
			caFingerprint, err := digestBytes(ca.Raw, certHash)
			if err != nil {
				return nil, fmt.Errorf("CA certificate fingerprint: %w", err)
			}
			caIssuer := &pkix.RDNSequence{}
			if _, err := asn1.Unmarshal(ca.RawIssuer, caIssuer); err != nil {
				return nil, fmt.Errorf("parsing CA issuer: %w", err)
			}
			signingCertificate.Cert = append(signingCertificate.Cert, &Cert{
				CertDigest: &CertDigest{
					DigestMethod: &AlgorithmMethod{Algorithm: certDigestAlgorithm},
					DigestValue:  caFingerprint,
				},
				IssuerSerial: &IssuerSerial{
					X509IssuerName:   s.serializeRDNSequence(caIssuer),
					X509SerialNumber: ca.SerialNumber.String(),
				},
			})
		}
	}

	signedSignatureProps := &SignedSignatureProperties{
		SigningTime:               s.opts.xadesConfig.TimestampFormatter(s.opts.timeNow()),
		SigningCertificate:        signingCertificate,
		SignerRole:                buildSignerRole(s.opts.xadesConfig.Role),
		SignaturePolicyIdentifier: buildPolicyIdentifier(s.opts.xadesConfig.Policy),
	}

	signedProps := &SignedProperties{
		ID:                        fmt.Sprintf(sigPropertiesIDFormat, s.opts.docID),
		SignedSignatureProperties: signedSignatureProps,
		SignedDataObjectProperties: buildSignedDataObjectProperties(
			s.opts.xadesConfig.DataObjectFormat,
			fmt.Sprintf(signedDataReferenceID, s.opts.docID),
		),
	}

	return signedProps, nil
}

func (s *Signature) serializeIssuer(cert *Certificate) string {
	if cert.issuer != nil {
		return s.serializeRDNSequence(cert.issuer)
	}
	return cert.Issuer()
}

func (s *Signature) serializeRDNSequence(issuer *pkix.RDNSequence) string {
	if s.opts.xadesConfig != nil {
		if serializer := s.opts.xadesConfig.IssuerSerializer; serializer != nil {
			return serializer(*issuer)
		}
	}
	return issuer.String()
}

func buildSignerRole(role XAdESSignerRole) *SignerRole {
	if role == "" {
		return nil
	}
	return &SignerRole{
		ClaimedRoles: &ClaimedRoles{
			ClaimedRole: []string{string(role)},
		},
	}
}

func buildPolicyIdentifier(policy *XAdESPolicyConfig) *PolicyIdentifier {
	if policy == nil {
		return nil
	}

	identifier := policy.URL
	if policy.Identifier != "" {
		identifier = policy.Identifier
	}

	pi := &PolicyIdentifier{
		SignaturePolicyID: &PolicySignaturePolicyID{
			SigPolicyID: PolicySigPolicyID{
				Identifier: Identifier{
					Value: identifier,
				},
				Description: policy.Description,
			},
			SigPolicyHash: &PolicySigPolicyHash{
				DigestMethod: &AlgorithmMethod{
					Algorithm: policy.Algorithm,
				},
				DigestValue: policy.Hash,
			},
		},
	}

	// When both Identifier and URL are set, add the URL as an SPURI qualifier
	if policy.Identifier != "" && policy.URL != "" {
		pi.SignaturePolicyID.SigPolicyQualifiers = &SigPolicyQualifiers{
			SigPolicyQualifier: []SigPolicyQualifier{
				{SPURI: policy.URL},
			},
		}
	}

	return pi
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
