//go:build !windows && apcera
// +build !windows,apcera

package gss_test

import (
	"testing"

	"github.com/bodgit/tsig/gss"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestExchangeCredentials(t *testing.T) {
	t.Parallel()

	assert.ErrorIs(t, testExchangeCredentials(t), gss.ErrNotSupported)
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
