module github.com/bodgit/tsig

require (
	github.com/alexbrainman/sspi v0.0.0-20180613141037-e580b900e9f5
	github.com/apcera/gssapi v0.0.0-20161010215902-5fb4217df13b
	github.com/enceve/crypto v0.0.0-20160707101852-34d48bb93815
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-uuid v1.0.1 // indirect
	github.com/jcmturner/gofork v0.0.0-20180107083740-2aebee971930 // indirect
	github.com/miekg/dns v1.0.7
	github.com/stretchr/testify v1.3.0
	golang.org/x/crypto v0.0.0-20190103213133-ff983b9c42bc // indirect
	golang.org/x/net v0.0.0-20190110200230-915654e7eabc // indirect
	gopkg.in/jcmturner/aescts.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/dnsutils.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/goidentity.v3 v3.0.0 // indirect
	gopkg.in/jcmturner/gokrb5.v6 v6.1.1
	gopkg.in/jcmturner/rpc.v1 v1.1.0 // indirect
)

replace gopkg.in/jcmturner/gokrb5.v6 v6.1.1 => github.com/jcmturner/gokrb5 v6.1.2-0.20190120135749-818e5f445123+incompatible
