package gss

import (
	"encoding/hex"
	"fmt"
	"github.com/bodgit/tsig"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"math/rand"
	"net"
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

func exchangeTKEY(host, keyname string, input []byte) ([]byte, error) {

	client := &dns.Client{
		Net:           "tcp",
		TsigAlgorithm: map[string]*dns.TsigAlgorithm{tsig.Gss: {nil, nil}},
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

	msg.Id = dns.Id()

	now := time.Now().Unix()

	msg.Extra[0] = &dns.TKEY{
		Hdr: dns.RR_Header{
			Name:   keyname,
			Rrtype: dns.TypeTKEY,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
		Algorithm:  tsig.Gss,
		Mode:       3,
		Inception:  uint32(now),
		Expiration: uint32(now),
		KeySize:    uint16(len(input)),
		Key:        hex.EncodeToString(input),
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}

	var rr *dns.Msg
	var errs error
	for _, addr := range addrs {
		rr, _, err = client.Exchange(msg, net.JoinHostPort(addr, "53"))
		if err == nil {
			break
		}
		errs = multierror.Append(errs, err)
	}

	if rr == nil {
		return nil, errs
	}

	if rr.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: %s (%d)", dns.RcodeToString[rr.Rcode], rr.Rcode)
	}

	// There should only ever be one answer RR of type TKEY
	if len(rr.Answer) != 1 || rr.Answer[0].Header().Rrtype != dns.TypeTKEY {
		return nil, fmt.Errorf("Received non-TKEY response")
	}

	if rr.Answer[0].Header().Name != keyname {
		return nil, fmt.Errorf("TKEY name does not match")
	}

	t := rr.Answer[0].(*dns.TKEY)
	if t.Error != 0 {
		return nil, fmt.Errorf("TKEY error: %d", t.Error)
	}

	key, err := hex.DecodeString(t.Key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
