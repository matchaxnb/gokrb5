module github.com/matchaxnb/gokrb5/v8

go 1.23.0

replace github.com/jcmturner/dnsutils/v2 => github.com/johanbrandhorst/dnsutils/v2 v2.0.0-20250626215550-85021c9d85c0

require (
	github.com/gorilla/sessions v1.2.1
	github.com/hashicorp/go-uuid v1.0.3
	github.com/jcmturner/aescts/v2 v2.0.0
	github.com/jcmturner/dnsutils/v2 v2.0.0
	github.com/jcmturner/gofork v1.7.6
	github.com/jcmturner/goidentity/v6 v6.0.1
	github.com/jcmturner/rpc/v2 v2.0.3
	github.com/stretchr/testify v1.8.1
	golang.org/x/crypto v0.37.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
