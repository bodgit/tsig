//go:build windows
// +build windows

package gss_test

import (
	"testing"

	"github.com/bodgit/tsig/gss"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestExchangeCredentials(t *testing.T) {
	t.Parallel()

	assert.Nil(t, testExchangeCredentials(t))
}

func TestExchangeKeytab(t *testing.T) {
	t.Parallel()

	assert.ErrorIs(t, testExchangeKeytab(t), gss.ErrNotSupported)
}

func TestNewClientWithConfig(t *testing.T) {
	t.Parallel()

	_, err := gss.NewClient(new(dns.Client), gss.WithConfig(""))
	assert.NotNil(t, err)
}

func TestNewServer(t *testing.T) {
	t.Parallel()

	if err := testNewServer(t); err != nil {
		t.Fatal(err)
	}
}
