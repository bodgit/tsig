// +build !windows,!apcera

package gss

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExchangeCredentials(t *testing.T) {
	assert.Nil(t, testExchangeCredentials(t))
}

func TestExchangeKeytab(t *testing.T) {
	assert.Nil(t, testExchangeKeytab(t))
}
