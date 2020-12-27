package util

import (
	"testing"
	"time"

	"github.com/bodgit/tsig"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

type FakeClient struct {
	Msg      *dns.Msg
	Duration time.Duration
	Err      error
}

func (c *FakeClient) Exchange(m *dns.Msg, address string) (*dns.Msg, time.Duration, error) {

	if c.Err != nil {
		return nil, 0, c.Err
	}

	return c.Msg, c.Duration, nil
}

func TestCalculateTimes(t *testing.T) {

	lifetime := uint32(3600)

	t0, t1, err := calculateTimes(tsig.TkeyModeDH, lifetime)
	assert.Nil(t, err)
	assert.Equal(t, lifetime, t1-t0)

	t0, t1, err = calculateTimes(tsig.TkeyModeGSS, lifetime)
	assert.Nil(t, err)
	assert.Equal(t, lifetime, t1-t0)

	t0, t1, err = calculateTimes(tsig.TkeyModeDelete, lifetime)
	assert.Nil(t, err)
	assert.Equal(t, uint32(0), t0)
	assert.Equal(t, uint32(0), t1)

	_, _, err = calculateTimes(tsig.TkeyModeServer, lifetime)
	assert.NotNil(t, err)
}

func TestExchangeTKEY(t *testing.T) {

	now := uint32(time.Now().Unix())

	goodTKEY := &dns.TKEY{
		Hdr: dns.RR_Header{
			Name:   "test.example.com.",
			Rrtype: dns.TypeTKEY,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
		Algorithm:  dns.GSS,
		Mode:       tsig.TkeyModeGSS,
		Inception:  now,
		Expiration: now + 3600,
		KeySize:    4,
		Key:        "deadbeef",
	}

	tables := map[string]struct {
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
		"ok": {
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
			algorithm:          dns.GSS,
			mode:               tsig.TkeyModeGSS,
			lifetime:           3600,
			expectedTKEY:       goodTKEY,
			expectedAdditional: []dns.RR{},
			expectedErr:        nil,
		},
	}

	for name, table := range tables {
		t.Run(name, func(t *testing.T) {
			tkey, additional, err := ExchangeTKEY(&table.client, table.host, table.keyname, table.algorithm, table.mode, table.lifetime, table.input, table.extra, table.tsigname, table.tsigalgo)
			assert.Equal(t, table.expectedTKEY, tkey)
			assert.Equal(t, table.expectedAdditional, additional)
			assert.Equal(t, table.expectedErr, err)
		})
	}
}
