module github.com/invopop/xmldsig

go 1.24.4

require (
	github.com/beevik/etree v1.6.0
	github.com/invopop/gobl v0.309.0
	github.com/russellhaering/goxmldsig v1.5.0
	github.com/stretchr/testify v1.11.1
	software.sslmate.com/src/go-pkcs12 v0.7.0
)

require (
	cloud.google.com/go v0.118.0 // indirect
	github.com/Masterminds/semver/v3 v3.3.1 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/invopop/jsonschema v0.13.1-0.20260331224545-b36d455c19d3 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mailru/easyjson v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/invopop/gobl => ../gobl
	github.com/invopop/gobl.ubl => ../gobl.ubl
)
