package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateTimes(t *testing.T) {
	t.Parallel()

	lifetime := uint32(3600)

	t0, t1, err := calculateTimes(TkeyModeDH, lifetime)
	assert.Nil(t, err)
	assert.Equal(t, lifetime, t1-t0)

	t0, t1, err = calculateTimes(TkeyModeGSS, lifetime)
	assert.Nil(t, err)
	assert.Equal(t, lifetime, t1-t0)

	t0, t1, err = calculateTimes(TkeyModeDelete, lifetime)
	assert.Nil(t, err)
	assert.Equal(t, uint32(0), t0)
	assert.Equal(t, uint32(0), t1)

	_, _, err = calculateTimes(TkeyModeServer, lifetime)
	assert.NotNil(t, err)
}
