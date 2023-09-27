package tsig_test

import (
	"errors"
	"testing"

	"github.com/bodgit/tsig"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

var (
	errProvider   = errors.New("provider error")
	testSignature = []byte("a good signature") //nolint:gochecknoglobals
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
	t.Parallel()

	tables := []struct {
		name      string
		provider  dns.TsigProvider
		signature []byte
		err       error
	}{
		{
			"good",
			tsig.MultiProvider(new(testProvider)),
			testSignature,
			nil,
		},
		{
			"unsupported good",
			tsig.MultiProvider(new(unsupportedProvider), new(testProvider)),
			testSignature,
			nil,
		},
		{
			"error good",
			tsig.MultiProvider(new(errorProvider), new(testProvider)),
			nil,
			errProvider,
		},
		{
			"all unsupported",
			tsig.MultiProvider(new(unsupportedProvider)),
			nil,
			dns.ErrKeyAlg,
		},
		{
			"nested",
			tsig.MultiProvider(tsig.MultiProvider(new(testProvider))),
			testSignature,
			nil,
		},
	}

	for _, table := range tables {
		table := table
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()
			b, err := table.provider.Generate(nil, nil)
			assert.Equal(t, table.signature, b)
			assert.Equal(t, table.err, err)
		})
	}
}

func TestMultiProviderVerify(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name     string
		provider dns.TsigProvider
		err      error
	}{
		{
			"good",
			tsig.MultiProvider(new(testProvider)),
			nil,
		},
		{
			"unsupported good",
			tsig.MultiProvider(new(unsupportedProvider), new(testProvider)),
			nil,
		},
		{
			"error good",
			tsig.MultiProvider(new(errorProvider), new(testProvider)),
			errProvider,
		},
		{
			"all unsuppored",
			tsig.MultiProvider(new(unsupportedProvider)),
			dns.ErrKeyAlg,
		},
	}

	for _, table := range tables {
		table := table
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()
			err := table.provider.Verify(nil, nil)
			assert.Equal(t, table.err, err)
		})
	}
}
