// Package xmldsig helps generate XML files with digital signatures.
package xmldsig

import (
	"errors"
	"time"

	"github.com/beevik/etree"
)

// Option function to be used for defining startup options
type Option func(o *options) error

// Namespaces defines special functionality for dealing with namespaces
type Namespaces map[string]string

type options struct {
	docID        string
	namespaces   Namespaces // map of namespace name to URL
	timestampURL string
	cert         *Certificate
	xadesOptions XAdESOptions
	timeNow      func() time.Time
}

// WithCertificate expects a path to a file containing a PKCS12 (.p12 or .pfx) certificate
// file, and a password used to open it.
func WithCertificate(cert *Certificate) Option {
	return func(o *options) error {
		o.cert = cert
		return nil
	}
}

// WithDocID assigns a document ID to the signatures
func WithDocID(id string) Option {
	return func(o *options) error {
		o.docID = id
		return nil
	}
}

// WithTimestamp will add an official timestamp to the signature.
func WithTimestamp(url string) Option {
	return func(o *options) error {
		o.timestampURL = url
		return nil
	}
}

// WithRawOptions allows callers to control the low-level XAdES behavior directly.
func WithRawOptions(opts XAdESOptions) Option {
	return func(o *options) error {
		o.xadesOptions = opts
		return nil
	}
}

// WithCurrentTime allows a callback to be provided in order to using a
// different signing time method. This is especially useful for testing.
// Default is to provide `time.Now().UTC()`.
func WithCurrentTime(fn func() time.Time) Option {
	return func(o *options) error {
		o.timeNow = fn
		return nil
	}
}

// WithNamespace is used to define all the namespaces that must be included in
// canonicalization processes. DSig requires each segment that is used in a hash
// to reference all previously defined namespaces, even if they are not used inside
// the current segment.
func WithNamespace(name, url string) Option {
	return func(o *options) error {
		if name == "" {
			return errors.New("cannot add anonymous namespace")
		}
		o.namespaces[name] = url
		return nil
	}
}

// Sign the provided data
func Sign(data []byte, opts ...Option) (*Signature, error) {
	return newSignature(data, opts...)
}

// Add will add the namespace and return a new instance of the map without
// modifying the original.
func (ns Namespaces) Add(name, url string) Namespaces {
	ns2 := make(Namespaces)
	for k, v := range ns {
		ns2[k] = v
	}
	ns2[name] = url
	return ns2
}

func (ns Namespaces) defs() []etree.Attr {
	attrs := make([]etree.Attr, 0)
	for k, v := range ns {
		if k == "" {
			attrs = append(attrs, etree.Attr{
				Space: "",
				Key:   "xmlns",
				Value: v,
			})
		} else {
			attrs = append(attrs, etree.Attr{
				Space: "xmlns",
				Key:   k,
				Value: v,
			})
		}
	}
	return attrs
}
