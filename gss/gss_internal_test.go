package gss

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateTKEYName(t *testing.T) {
	t.Parallel()

	tkey, err := generateTKEYName("host.example.com")
	require.NoError(t, err)
	assert.Regexp(t, `^\d+\.sig-host\.example\.com\.$`, tkey)
}

func TestGenerateSPN(t *testing.T) {
	t.Parallel()

	spn := generateSPN("host.example.com")
	assert.Equal(t, "DNS/host.example.com", spn)

	spn = generateSPN("host.example.com.")
	assert.Equal(t, "DNS/host.example.com", spn)
}
