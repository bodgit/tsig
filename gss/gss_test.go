package gss_test

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/bodgit/tsig"
	"github.com/bodgit/tsig/gss"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	multierror "github.com/hashicorp/go-multierror"
	dnsv1 "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

const dnsClientTransport = "tcp"

func testEnvironmentVariables(t *testing.T) (string, string, string, string, string, string) {
	t.Helper()

	var (
		host     string
		port     = "53"
		realm    string
		username string
		password string
		keytab   string
		errs     *multierror.Error
	)

	for _, env := range []struct {
		ptr      *string
		name     string
		optional bool
	}{
		{
			&host,
			"DNS_HOST",
			false,
		},
		{
			&port,
			"DNS_PORT",
			true,
		},
		{
			&realm,
			"DNS_REALM",
			false,
		},
		{
			&username,
			"DNS_USERNAME",
			false,
		},
		{
			&password,
			"DNS_PASSWORD",
			false,
		},
		{
			&keytab,
			"DNS_KEYTAB",
			runtime.GOOS == "windows",
		},
	} {
		if v, ok := os.LookupEnv(env.name); ok {
			*env.ptr = v
		} else if !env.optional {
			errs = multierror.Append(errs, fmt.Errorf("%s is not set", env.name))
		}
	}

	if errs.ErrorOrNil() != nil {
		t.Fatal(errs)
	}

	return host, port, realm, username, password, keytab
}

func testExchange(t *testing.T) (err error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	//nolint:dogsled
	host, port, _, _, _, _ := testEnvironmentVariables(t)

	dnsClient := new(dnsv1.Client)
	dnsClient.Net = dnsClientTransport

	gssClient, err := gss.NewClient(dnsClient, gss.WithLogger(testr.New(t)))
	if err != nil {
		return err
	}

	defer func() {
		err = multierror.Append(err, gssClient.Close()).ErrorOrNil()
	}()

	keyname, _, err := gssClient.NegotiateContext(net.JoinHostPort(host, port))
	if err != nil {
		return err
	}

	dnsClient.TsigProvider = gssClient

	msg := new(dnsv1.Msg)
	msg.SetUpdate(dnsv1.Fqdn("example.com"))

	insert, err := dnsv1.NewRR("test.example.com. 300 A 192.0.2.1")
	if err != nil {
		return err
	}

	msg.Insert([]dnsv1.RR{insert})

	msg.SetTsig(keyname, tsig.GSS, 300, time.Now().Unix())

	rr, _, err := dnsClient.Exchange(msg, net.JoinHostPort(host, port))
	if err != nil {
		return err
	}

	if rr.Rcode != dnsv1.RcodeSuccess {
		return fmt.Errorf("DNS error: %s (%d)", dnsv1.RcodeToString[rr.Rcode], rr.Rcode)
	}

	return gssClient.DeleteContext(keyname)
}

func testExchangeCredentials(t *testing.T) (err error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	host, port, realm, username, password, _ := testEnvironmentVariables(t)

	dnsClient := new(dnsv1.Client)
	dnsClient.Net = dnsClientTransport

	gssClient, err := gss.NewClient(dnsClient)
	if err != nil {
		return err
	}

	defer func() {
		err = multierror.Append(err, gssClient.Close()).ErrorOrNil()
	}()

	if err = gssClient.SetLogger(testr.New(t)); err != nil {
		return err
	}

	keyname, _, err := gssClient.NegotiateContextWithCredentials(net.JoinHostPort(host, port), realm, username, password)
	if err != nil {
		return err
	}

	return gssClient.DeleteContext(keyname)
}

func testExchangeKeytab(t *testing.T) (err error) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	host, port, realm, username, _, keytab := testEnvironmentVariables(t)

	dnsClient := new(dnsv1.Client)
	dnsClient.Net = dnsClientTransport

	gssClient, err := gss.NewClient(dnsClient, gss.WithLogger(testr.New(t)))
	if err != nil {
		return err
	}

	defer func() {
		err = multierror.Append(err, gssClient.Close()).ErrorOrNil()
	}()

	keyname, _, err := gssClient.NegotiateContextWithKeytab(net.JoinHostPort(host, port), realm, username, keytab)
	if err != nil {
		return err
	}

	return gssClient.DeleteContext(keyname)
}

func TestExchange(t *testing.T) {
	t.Parallel()

	assert.NoError(t, testExchange(t))
}

func TestNewClientWithLogger(t *testing.T) {
	t.Parallel()

	_, err := gss.NewClient(new(dnsv1.Client), gss.WithLogger(logr.Discard()))
	assert.NoError(t, err)
}
