module github.com/wop-platform/wop-go-sdk

go 1.27.0

require (
	github.com/cucumber/godog v0.16.0
	github.com/emmansun/gmsm v0.44.1
	golang.org/x/exp v0.0.0-20260824195058-e88cd73687aa
)

require (
	github.com/cucumber/gherkin/go/v42 v42.0.0 // indirect
	github.com/cucumber/messages/go/v34 v34.2.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-memdb v1.3.5 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

// CVE-2026-5160: x/tools@v0.49.0 (latest) pins goldmark v1.4.13 (renderer/html
// XSS). No package imports goldmark, but the module graph must resolve >=1.7.17.
// Drop once x/tools raises its goldmark requirement.
replace github.com/yuin/goldmark => github.com/yuin/goldmark v1.7.17
