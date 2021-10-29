// +build !windows,!apcera

package gss

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestExchangeCredentials(t *testing.T) {
	assert.Nil(t, testExchangeCredentials(t))
}

func TestExchangeKeytab(t *testing.T) {
	assert.Nil(t, testExchangeKeytab(t))
}

func TestNewClientWithConfig(t *testing.T) {
	_, err := NewClient(new(dns.Client), WithConfig(""))
	assert.Nil(t, err)
}
