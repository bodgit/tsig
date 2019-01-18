package gss

import (
	"regexp"
	"testing"

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
