/*
Package gss implements RFC 3645 GSS-TSIG functions for the
github.com/miekg/dns package. This permits sending signed dynamic DNS update
messages to Windows servers that have the zone require "Secure only" updates.

Basic usage pattern for setting up a client:

        host := "ns.example.com"

        c, err := gss.New()
        if err != nil {
                panic(err)
        }
        defer c.Close()

        // Negotiate a context with the chosen server
        keyname, _, err := c.NegotiateContext(host)
        if err != nil {
                panic(err)
        }

        client := &dns.Client{
                Net:           "tcp",
                TsigAlgorithm: map[string]*dns.TsigAlgorithm{tsig.GSS: {c.GenerateGSS, c.VerifyGSS}},
                TsigSecret:    map[string]string{*keyname: ""},
        }

        // Do stuff here with the DNS client as usual

        msg := new(dns.Msg)
        msg.SetUpdate(dns.Fqdn("example.com"))

        insert, err := dns.NewRR("test.example.com. 300 A 192.0.2.1")
        if err != nil {
                panic(err)
        }
        msg.Insert([]dns.RR{insert})

        msg.SetTsig(*keyname, tsig.GSS, 300, time.Now().Unix())

        rr, _, err := client.Exchange(msg, net.JoinHostPort(host, "53"))
        if err != nil {
                panic(err)
        }

        if rr.Rcode != dns.RcodeSuccess {
                fmt.Printf("DNS error: %s (%d)\n", dns.RcodeToString[rr.Rcode], rr.Rcode)
        }

        // Cleanup the context
        err = c.DeleteContext(keyname)
        if err != nil {
                panic(err)
        }

Under the hood, GSSAPI is used on non-Windows platforms by locating and
loading a native shared library whilst SSPI is used instead on Windows
platforms.
*/
package gss

import (
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"time"
)

func generateTKEYName(host string) string {

	seed := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(seed)

	return dns.Fqdn(fmt.Sprintf("%d.sig-%s", rng.Int31(), host))
}

func generateSPN(host string) string {

	return fmt.Sprintf("DNS/%s", host)
}
