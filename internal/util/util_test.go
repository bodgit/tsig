package util_test

import (
	"errors"
	"testing"
	"time"

	"github.com/bodgit/tsig"
	"github.com/bodgit/tsig/internal/util"
	dnsv1 "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type FakeClient struct {
	Msg      *dnsv1.Msg
	Duration time.Duration
	Err      error
}

func (c *FakeClient) Exchange(_ *dnsv1.Msg, _ string) (*dnsv1.Msg, time.Duration, error) {
	if c.Err != nil {
		return nil, 0, c.Err
	}

	return c.Msg, c.Duration, nil
}

//nolint:funlen
func TestExchangeTKEY(t *testing.T) {
	t.Parallel()

	now := uint32(time.Now().Unix())

	goodTKEY := &dnsv1.TKEY{
		Hdr: dnsv1.RR_Header{
			Name:   "test.example.com.",
			Rrtype: dnsv1.TypeTKEY,
			Class:  dnsv1.ClassANY,
			Ttl:    0,
		},
		Algorithm:  tsig.GSS,
		Mode:       util.TkeyModeGSS,
		Inception:  now,
		Expiration: now + 3600,
		KeySize:    4,
		Key:        "deadbeef",
	}

	tables := []struct {
		name               string
		client             FakeClient
		host               string
		keyname            string
		algorithm          string
		mode               uint16
		lifetime           uint32
		input              []byte
		extra              []dnsv1.RR
		tsigname           string
		tsigalgo           string
		expectedTKEY       *dnsv1.TKEY
		expectedAdditional []dnsv1.RR
		expectedErr        error
	}{
		{
			name: "ok",
			client: FakeClient{
				Msg: &dnsv1.Msg{
					Answer: []dnsv1.RR{
						goodTKEY,
					},
				},
				Duration: 0,
				Err:      nil,
			},
			host:               "ns.example.com.",
			keyname:            "test.example.com.",
			algorithm:          tsig.GSS,
			mode:               util.TkeyModeGSS,
			lifetime:           3600,
			expectedTKEY:       goodTKEY,
			expectedAdditional: []dnsv1.RR{},
			expectedErr:        nil,
		},
	}

	for _, table := range tables {
		table := table
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()
			//nolint:lll
			tkey, additional, err := util.ExchangeTKEY(&table.client, table.host, table.keyname, table.algorithm, table.mode, table.lifetime, table.input, table.extra, table.tsigname, table.tsigalgo)
			assert.Equal(t, table.expectedTKEY, tkey)
			assert.Equal(t, table.expectedAdditional, additional)
			assert.Equal(t, table.expectedErr, err)
		})
	}
}

//nolint:funlen,goconst
func TestCopyDNSClient(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name   string
		client dnsv1.Client
		net    string
		err    error
	}{
		{
			"tcp",
			dnsv1.Client{
				Net: "tcp",
			},
			"tcp",
			nil,
		},
		{
			"udp",
			dnsv1.Client{
				Net: "udp",
			},
			"tcp",
			nil,
		},
		{
			"udp4",
			dnsv1.Client{
				Net: "udp4",
			},
			"tcp4",
			nil,
		},
		{
			"udp6",
			dnsv1.Client{
				Net: "udp6",
			},
			"tcp6",
			nil,
		},
		{
			"invalid",
			dnsv1.Client{
				Net: "invalid",
			},
			"tcp6",
			errors.New("unsupported transport 'invalid'"),
		},
	}

	for _, table := range tables {
		table := table
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()
			client, err := util.CopyDNSClient(&table.client)
			if table.err == nil {
				assert.Equal(t, table.net, client.Net)
			}
			assert.Equal(t, table.err, err)
		})
	}
}

type mockTsigProvider struct {
	Name string
}

func (f mockTsigProvider) Generate(_ []byte, _ *dnsv1.TSIG) ([]byte, error) {
	return nil, nil
}

func (f mockTsigProvider) Verify(_ []byte, _ *dnsv1.TSIG) error {
	return nil
}

func TestCopyDNSClient_shallow_copy(t *testing.T) {
	t.Parallel()

	dnsClient := &dnsv1.Client{
		Net:          "udp",
		TsigProvider: &mockTsigProvider{Name: "original"},
	}

	client, err := util.CopyDNSClient(dnsClient)
	require.NoError(t, err)

	client.TsigProvider = &mockTsigProvider{Name: "copy"}

	originalProvider, ok := dnsClient.TsigProvider.(*mockTsigProvider)
	require.True(t, ok)

	assert.Equal(t, "original", originalProvider.Name)
	assert.Equal(t, "udp", dnsClient.Net)
	assert.Nil(t, dnsClient.TsigSecret)

	copyProvider, ok := client.TsigProvider.(*mockTsigProvider)
	require.True(t, ok)

	assert.Equal(t, "copy", copyProvider.Name)
	assert.Equal(t, "tcp", client.Net)
	assert.NotNil(t, client.TsigSecret)
}
