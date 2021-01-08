package tsig

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

var (
	errProvider   = errors.New("provider error")
	testSignature = []byte("a good signature")
)

type unsupportedProvider struct{}

func (unsupportedProvider) Generate(_ []byte, _ *dns.TSIG) ([]byte, error) {
	return nil, dns.ErrKeyAlg
}

func (unsupportedProvider) Verify(_ []byte, _ *dns.TSIG) error {
	return dns.ErrKeyAlg
}

type errorProvider struct{}

func (errorProvider) Generate(_ []byte, _ *dns.TSIG) ([]byte, error) {
	return nil, errProvider
}

func (errorProvider) Verify(_ []byte, _ *dns.TSIG) error {
	return errProvider
}

type testProvider struct{}

func (testProvider) Generate(_ []byte, _ *dns.TSIG) ([]byte, error) {
	return testSignature, nil
}

func (testProvider) Verify(_ []byte, _ *dns.TSIG) error {
	return nil
}

func TestMultiProviderGenerate(t *testing.T) {
	tables := map[string]struct {
		provider  dns.TsigProvider
		signature []byte
		err       error
	}{
		"good": {
			MultiProvider(new(testProvider)),
			testSignature,
			nil,
		},
		"unsupported good": {
			MultiProvider(new(unsupportedProvider), new(testProvider)),
			testSignature,
			nil,
		},
		"error good": {
			MultiProvider(new(errorProvider), new(testProvider)),
			nil,
			errProvider,
		},
		"all unsupported": {
			MultiProvider(new(unsupportedProvider)),
			nil,
			dns.ErrKeyAlg,
		},
		"nested": {
			MultiProvider(MultiProvider(new(testProvider))),
			testSignature,
			nil,
		},
	}

	for name, table := range tables {
		t.Run(name, func(t *testing.T) {
			b, err := table.provider.Generate(nil, nil)
			assert.Equal(t, table.signature, b)
			assert.Equal(t, table.err, err)
		})
	}
}

func TestMultiProviderVerify(t *testing.T) {
	tables := map[string]struct {
		provider dns.TsigProvider
		err      error
	}{
		"good": {
			MultiProvider(new(testProvider)),
			nil,
		},
		"unsupported good": {
			MultiProvider(new(unsupportedProvider), new(testProvider)),
			nil,
		},
		"error good": {
			MultiProvider(new(errorProvider), new(testProvider)),
			errProvider,
		},
		"all unsuppored": {
			MultiProvider(new(unsupportedProvider)),
			dns.ErrKeyAlg,
		},
	}

	for name, table := range tables {
		t.Run(name, func(t *testing.T) {
			err := table.provider.Verify(nil, nil)
			assert.Equal(t, table.err, err)
		})
	}
}
