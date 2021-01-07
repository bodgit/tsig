package gss

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/bodgit/tsig"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestGenerateTKEYName(t *testing.T) {

	tkey := generateTKEYName("host.example.com")
	assert.Regexp(t, regexp.MustCompile("^\\d+\\.sig-host\\.example\\.com\\.$"), tkey)
}

func TestGenerateSPN(t *testing.T) {

	spn := generateSPN("host.example.com")
	assert.Equal(t, "DNS/host.example.com", spn)

	spn = generateSPN("host.example.com.")
	assert.Equal(t, "DNS/host.example.com", spn)
}

func testEnvironmentVariables(t *testing.T) (string, string, string, string, string, string) {
	host, ok := os.LookupEnv("DNS_HOST")
	if !ok {
		t.Fatal("$DNS_HOST not set")
	}

	port, ok := os.LookupEnv("DNS_PORT")
	if !ok {
		port = "53"
	}

	realm, ok := os.LookupEnv("DNS_REALM")
	if !ok {
		t.Fatal("$DNS_REALM not set")
	}

	username, ok := os.LookupEnv("DNS_USERNAME")
	if !ok {
		t.Fatal("$DNS_USERNAME not set")
	}

	password, ok := os.LookupEnv("DNS_PASSWORD")
	if !ok {
		t.Fatal("$DNS_PASSWORD not set")
	}

	keytab, ok := os.LookupEnv("DNS_KEYTAB")
	if !ok {
		t.Fatal("$DNS_KEYTAB not set")
	}

	return host, port, realm, username, password, keytab
}

func testExchange(t *testing.T) error {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	host, port, _, _, _, _ := testEnvironmentVariables(t)

	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"

	gssClient, err := NewClient(dnsClient)
	if err != nil {
		return err
	}
	defer gssClient.Close()

	keyname, _, err := gssClient.NegotiateContext(net.JoinHostPort(host, port))
	if err != nil {
		return err
	}

	dnsClient.TsigProvider = gssClient

	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn("example.com"))

	insert, err := dns.NewRR("test.example.com. 300 A 192.0.2.1")
	if err != nil {
		panic(err)
	}
	msg.Insert([]dns.RR{insert})

	msg.SetTsig(keyname, tsig.GSS, 300, time.Now().Unix())

	rr, _, err := dnsClient.Exchange(msg, net.JoinHostPort(host, port))
	if err != nil {
		panic(err)
	}

	if rr.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS error: %s (%d)\n", dns.RcodeToString[rr.Rcode], rr.Rcode)
	}

	err = gssClient.DeleteContext(keyname)
	if err != nil {
		return err
	}

	return nil
}

func testExchangeCredentials(t *testing.T) error {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	host, port, realm, username, password, _ := testEnvironmentVariables(t)

	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"

	gssClient, err := NewClient(dnsClient)
	if err != nil {
		return err
	}
	defer gssClient.Close()

	keyname, _, err := gssClient.NegotiateContextWithCredentials(net.JoinHostPort(host, port), realm, username, password)
	if err != nil {
		return err
	}

	err = gssClient.DeleteContext(keyname)
	if err != nil {
		return err
	}

	return nil
}

func testExchangeKeytab(t *testing.T) error {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	host, port, realm, username, _, keytab := testEnvironmentVariables(t)

	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"

	gssClient, err := NewClient(dnsClient)
	if err != nil {
		return err
	}
	defer gssClient.Close()

	keyname, _, err := gssClient.NegotiateContextWithKeytab(net.JoinHostPort(host, port), realm, username, keytab)
	if err != nil {
		return err
	}

	err = gssClient.DeleteContext(keyname)
	if err != nil {
		return err
	}

	return nil
}

func TestExchange(t *testing.T) {
	assert.Nil(t, testExchange(t))
}
