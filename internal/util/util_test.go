package util_test

import (
	"errors"
	"testing"
	"time"

	"github.com/bodgit/tsig"
	"github.com/bodgit/tsig/internal/util"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

type FakeClient struct {
	Msg      *dns.Msg
	Duration time.Duration
	Err      error
}

func (c *FakeClient) Exchange(_ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	if c.Err != nil {
		return nil, 0, c.Err
	}

	return c.Msg, c.Duration, nil
}

//nolint:funlen
func TestExchangeTKEY(t *testing.T) {
	t.Parallel()

	now := uint32(time.Now().Unix())

	goodTKEY := &dns.TKEY{
		Hdr: dns.RR_Header{
			Name:   "test.example.com.",
			Rrtype: dns.TypeTKEY,
			Class:  dns.ClassANY,
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
		extra              []dns.RR
		tsigname           string
		tsigalgo           string
		expectedTKEY       *dns.TKEY
		expectedAdditional []dns.RR
		expectedErr        error
	}{
		{
			name: "ok",
			client: FakeClient{
				Msg: &dns.Msg{
					Answer: []dns.RR{
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
			expectedAdditional: []dns.RR{},
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

//nolint:funlen
func TestCopyDNSClient(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name   string
		client dns.Client
		net    string
		err    error
	}{
		{
			"tcp",
			dns.Client{
				Net: "tcp",
			},
			"tcp",
			nil,
		},
		{
			"udp",
			dns.Client{
				Net: "udp",
			},
			"tcp",
			nil,
		},
		{
			"udp4",
			dns.Client{
				Net: "udp4",
			},
			"tcp4",
			nil,
		},
		{
			"udp6",
			dns.Client{
				Net: "udp6",
			},
			"tcp6",
			nil,
		},
		{
			"invalid",
			dns.Client{
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
