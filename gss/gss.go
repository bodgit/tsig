/*
Package gss implements RFC 3645 GSS-TSIG functions. This permits sending
signed dynamic DNS update messages to Windows servers that have the zone
require "Secure only" updates.

Example client:

        import (
                "fmt"
                "net"
                "time"

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

                host := "ns.example.com"

                // Negotiate a context with the chosen server using the
                // current user. See also
                // gssClient.NegotiateContextWithCredentials() and
                // gssClient.NegotiateContextWithKeytab() for alternatives
                keyname, _, err := gssClient.NegotiateContext(host)
                if err != nil {
                        panic(err)
                }

                dnsClient.TsigGSS = gssClient
                dnsClient.TsigSecret = map[string]string{keyname: ""}

                // Use the DNS client as normal

                msg := new(dns.Msg)
                msg.SetUpdate(dns.Fqdn("example.com"))

                insert, err := dns.NewRR("test.example.com. 300 A 192.0.2.1")
                if err != nil {
                        panic(err)
                }
                msg.Insert([]dns.RR{insert})

                msg.SetTsig(keyname, dns.GSS, 300, time.Now().Unix())

                rr, _, err := dnsClient.Exchange(msg, net.JoinHostPort(host, "53"))
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
	"fmt"
	"math/rand"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
)

func generateTKEYName(host string) string {

	seed := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(seed)

	return dns.Fqdn(fmt.Sprintf("%d.sig-%s", rng.Int31(), host))
}

func generateSPN(host string) string {

	if dns.IsFqdn(host) {
		return fmt.Sprintf("DNS/%s", host[:len(host)-1])
	}

	return fmt.Sprintf("DNS/%s", host)
}

func (c *Client) close() error {

	c.m.RLock()
	keys := make([]string, 0, len(c.ctx))
	for k := range c.ctx {
		keys = append(keys, k)
	}
	c.m.RUnlock()

	var errs error
	for _, k := range keys {
		errs = multierror.Append(errs, c.DeleteContext(k))
	}

	return errs
}
