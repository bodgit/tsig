```golang
package main

import (
	"fmt"
	"github.com/bodgit/tsig"
	"github.com/miekg/dns"
	"net"
	"time"
)

func main() {

	c, err := tsig.New()
	if err != nil {
		panic(err)
	}
	defer c.Close()

	keyname, err := c.NegotiateContext("ns.example.com")
	if err != nil {
		panic(err)
	}

	client := &dns.Client{
		Net:           "tcp",
		TsigAlgorithm: map[string]*dns.TsigAlgorithm{tsig.GssTsig: {c.GenerateGssTsig, c.VerifyGssTsig}},
		TsigSecret:    map[string]string{*keyname: ""},
	}

	// Do stuff here

	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn("example.com"))

	insert, err := dns.NewRR("test.example.com. 300 A 192.0.2.1")
	if err != nil {
		panic(err)
	}
	msg.Insert([]dns.RR{insert})

	msg.SetTsig(*keyname, tsig.GssTsig, 300, time.Now().Unix())

	addrs, err := net.LookupHost("ns.example.com")
	if err != nil {
		panic(err)
	}

	rr, _, err := client.Exchange(msg, net.JoinHostPort(addrs[0], "53"))
	if err != nil {
		panic(err)
	}

	if rr.Rcode != dns.RcodeSuccess {
		fmt.Printf("DNS error: %s (%d)\n", dns.RcodeToString[rr.Rcode], rr.Rcode)
	}

	// Cleanup

	err = c.DeleteContext(keyname)
	if err != nil {
		panic(err)
	}
}
```
