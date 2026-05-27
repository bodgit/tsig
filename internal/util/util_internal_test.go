package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateTimes(t *testing.T) {
	t.Parallel()

	lifetime := uint32(3600)

	t0, t1, err := calculateTimes(TkeyModeDH, lifetime)
	require.NoError(t, err)
	assert.Equal(t, lifetime, t1-t0)

	t0, t1, err = calculateTimes(TkeyModeGSS, lifetime)
	require.NoError(t, err)
	assert.Equal(t, lifetime, t1-t0)

	t0, t1, err = calculateTimes(TkeyModeDelete, lifetime)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), t0)
	assert.Equal(t, uint32(0), t1)

	_, _, err = calculateTimes(TkeyModeServer, lifetime)
	assert.Error(t, err)
}
