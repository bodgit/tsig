/*
Package gss implements RFC 3645 GSS-TSIG functions. This permits sending
signed dynamic DNS update messages to Windows servers that have the zone
require "Secure only" updates.

Example client:

	import (
		"fmt"
		"time"

		"github.com/bodgit/tsig"
		"github.com/bodgit/tsig/gss"
		"github.com/miekg/dns"
	)

	func main() {
		dnsClient := new(dns.Client)
		dnsClient.Net = "tcp"

		gssClient, err := gss.NewClient(dnsClient)
		if err != nil {
			panic(err)
		}
		defer gssClient.Close()

		host := "ns.example.com:53"

		// Negotiate a context with the chosen server using the
		// current user. See also
		// gssClient.NegotiateContextWithCredentials() and
		// gssClient.NegotiateContextWithKeytab() for alternatives
		keyname, _, err := gssClient.NegotiateContext(host)
		if err != nil {
			panic(err)
		}

		dnsClient.TsigProvider = gssClient

		// Use the DNS client as normal

		msg := new(dns.Msg)
		msg.SetUpdate(dns.Fqdn("example.com"))

		insert, err := dns.NewRR("test.example.com. 300 A 192.0.2.1")
		if err != nil {
			panic(err)
		}
		msg.Insert([]dns.RR{insert})

		msg.SetTsig(keyname, tsig.GSS, 300, time.Now().Unix())

		rr, _, err := dnsClient.Exchange(msg, host)
		if err != nil {
			panic(err)
		}

		if rr.Rcode != dns.RcodeSuccess {
			fmt.Printf("DNS error: %s (%d)\n", dns.RcodeToString[rr.Rcode], rr.Rcode)
		}

		// Cleanup the context
		err = gssClient.DeleteContext(keyname)
		if err != nil {
			panic(err)
		}
	}

Under the hood, GSSAPI is used on platforms other than Windows whilst Windows
uses native SSPI which has a similar API.
*/
package gss

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/bodgit/tsig"
	dnsv1 "github.com/miekg/dns"
)

var (
	errNotSupported  = errors.New("not supported") //nolint:nolintlint,unused
	errDoesNotMatch  = errors.New("TKEY name does not match")
	errNoSuchContext = errors.New("no such context")
)

// gssNoVerify is a [dnsv1.TsigProvider] that skips any GSS-TSIG verification.
//
// BIND doesn't sign TKEY responses but Windows does, using the key you're
// currently negotiating so it creates a chicken & egg problem. According
// to the RFC, verification isn't needed as the TKEY response should be
// cryptographically secure anyway.
type gssNoVerify struct{}

func (*gssNoVerify) Generate(_ []byte, t *dnsv1.TSIG) ([]byte, error) {
	if dnsv1.CanonicalName(t.Algorithm) != tsig.GSS {
		return nil, dnsv1.ErrKeyAlg
	}

	return nil, dnsv1.ErrSecret
}

func (*gssNoVerify) Verify(_ []byte, t *dnsv1.TSIG) error {
	if dnsv1.CanonicalName(t.Algorithm) != tsig.GSS {
		return dnsv1.ErrKeyAlg
	}

	return nil
}

func generateTKEYName(host string) (string, error) {
	i, err := rand.Int(rand.Reader, big.NewInt(0x7fffffff))
	if err != nil {
		return "", err
	}

	return dnsv1.Fqdn(fmt.Sprintf("%d.sig-%s", i.Int64(), host)), nil
}

func generateSPN(host string) string {
	if dnsv1.IsFqdn(host) {
		return fmt.Sprintf("DNS/%s", host[:len(host)-1])
	}

	return fmt.Sprintf("DNS/%s", host)
}
