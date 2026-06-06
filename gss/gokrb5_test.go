//go:build !windows && !apcera
// +build !windows,!apcera

package gss_test

import (
	"testing"

	"github.com/bodgit/tsig/gss"
	dnsv1 "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestExchangeCredentials(t *testing.T) {
	t.Parallel()

	assert.NoError(t, testExchangeCredentials(t))
}

func TestExchangeKeytab(t *testing.T) {
	t.Parallel()

	assert.NoError(t, testExchangeKeytab(t))
}

func TestNewClientWithConfig(t *testing.T) {
	t.Parallel()

	_, err := gss.NewClient(new(dnsv1.Client), gss.WithConfig(""))
	assert.NoError(t, err)
}
