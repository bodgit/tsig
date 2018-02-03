[![Go Report Card](https://goreportcard.com/badge/github.com/bodgit/tsig)](https://goreportcard.com/report/github.com/bodgit/tsig)
[![GoDoc](https://godoc.org/github.com/bodgit/tsig?status.svg)](https://godoc.org/github.com/bodgit/tsig)

```golang
package main

import (
	"fmt"
	"github.com/bodgit/tsig"
	"github.com/bodgit/tsig/gss"
	"github.com/miekg/dns"
	"net"
	"time"
)

func main() {

	c, err := gss.New()
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
		TsigAlgorithm: map[string]*dns.TsigAlgorithm{tsig.Gss: {c.GenerateGssTsig, c.VerifyGssTsig}},
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

	msg.SetTsig(*keyname, tsig.Gss, 300, time.Now().Unix())

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
