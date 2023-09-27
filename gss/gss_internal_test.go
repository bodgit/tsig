package gss

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateTKEYName(t *testing.T) {
	t.Parallel()

	tkey, err := generateTKEYName("host.example.com")
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`^\d+\.sig-host\.example\.com\.$`), tkey)
}

func TestGenerateSPN(t *testing.T) {
	t.Parallel()

	spn := generateSPN("host.example.com")
	assert.Equal(t, "DNS/host.example.com", spn)

	spn = generateSPN("host.example.com.")
	assert.Equal(t, "DNS/host.example.com", spn)
}
