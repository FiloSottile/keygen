module filippo.io/keygen

go 1.20

require (
	filippo.io/bigmod v0.0.3
	golang.org/x/crypto v0.7.0
)

require golang.org/x/sys v0.22.0 // indirect

// Testing dependencies.
require (
	github.com/canonical/go-sp800.90a-drbg v0.0.0-20210314144037-6eeb1040d6c3
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)
