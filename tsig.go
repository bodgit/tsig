package tsig

import (
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"time"
)

const (
	GssTsig = "gss-tsig."
)

func generateTKEYName(host string) string {

	seed := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(seed)

	return dns.Fqdn(fmt.Sprintf("%d.sig-%s", rng.Int31(), host))
}

func generateSPN(host string) string {

	return fmt.Sprintf("DNS/%s", host)
}

func bootstrapDNSClient(keyname string) (*dns.Client, *dns.Msg) {

	client := &dns.Client{
		Net:           "tcp",
		TsigAlgorithm: map[string]*dns.TsigAlgorithm{GssTsig: {nil, nil}},
		TsigSecret:    map[string]string{keyname: ""},
	}

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
		Question: make([]dns.Question, 1),
		Extra:    make([]dns.RR, 1),
	}

	msg.Question[0] = dns.Question{
		Name:   keyname,
		Qtype:  dns.TypeTKEY,
		Qclass: dns.ClassANY,
	}

	return client, msg
}

func generateTKEY(keyname string, tkey []byte) *dns.TKEY {

	now := time.Now().Unix()

	return &dns.TKEY{
		Hdr: dns.RR_Header{
			Name:   keyname,
			Rrtype: dns.TypeTKEY,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
		Algorithm:  GssTsig,
		Mode:       3,
		Inception:  uint32(now),
		Expiration: uint32(now),
		KeySize:    uint16(len(tkey)),
		Key:        hex.EncodeToString(tkey),
	}
}
