package tsig_test

import (
	"errors"
	"testing"

	"github.com/bodgit/tsig"
	dnsv1 "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

var (
	errProvider   = errors.New("provider error")
	testSignature = []byte("a good signature") //nolint:gochecknoglobals
)

type unsupportedProvider struct{}

func (unsupportedProvider) Generate(_ []byte, _ *dnsv1.TSIG) ([]byte, error) {
	return nil, dnsv1.ErrKeyAlg
}

func (unsupportedProvider) Verify(_ []byte, _ *dnsv1.TSIG) error {
	return dnsv1.ErrKeyAlg
}

type errorProvider struct{}

func (errorProvider) Generate(_ []byte, _ *dnsv1.TSIG) ([]byte, error) {
	return nil, errProvider
}

func (errorProvider) Verify(_ []byte, _ *dnsv1.TSIG) error {
	return errProvider
}

type testProvider struct{}

func (testProvider) Generate(_ []byte, _ *dnsv1.TSIG) ([]byte, error) {
	return testSignature, nil
}

func (testProvider) Verify(_ []byte, _ *dnsv1.TSIG) error {
	return nil
}

func TestMultiProviderGenerate(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name      string
		provider  dnsv1.TsigProvider
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
			dnsv1.ErrKeyAlg,
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
		provider dnsv1.TsigProvider
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
			dnsv1.ErrKeyAlg,
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
