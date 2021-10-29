// +build !windows,apcera

package gss

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestExchangeCredentials(t *testing.T) {
	assert.Equal(t, errNotSupported, testExchangeCredentials(t))
}

func TestExchangeKeytab(t *testing.T) {
	assert.Equal(t, errNotSupported, testExchangeKeytab(t))
}

func TestNewClientWithConfig(t *testing.T) {
	_, err := NewClient(new(dns.Client), WithConfig(""))
	assert.NotNil(t, err)
}
