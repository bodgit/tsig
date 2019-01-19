package tsig

import (
	"testing"
	"time"

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

func TestSplitHostPort(t *testing.T) {

	host, port := SplitHostPort("host.example.com.")
	assert.Equal(t, "host.example.com.", host)
	assert.Equal(t, "53", port)

	host, port = SplitHostPort("host.example.com.:8053")
	assert.Equal(t, "host.example.com.", host)
	assert.Equal(t, "8053", port)
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
		Algorithm:  GSS,
		Mode:       TkeyModeGSS,
		Inception:  now,
		Expiration: now + 3600,
		KeySize:    4,
		Key:        "deadbeef",
	}

	cases := []struct {
		client             FakeClient
		host               string
		keyname            string
		algorithm          string
		mode               uint16
		lifetime           uint32
		input              []byte
		extra              []dns.RR
		tsigname           *string
		tsigalgo           *string
		tsigmac            *string
		expectedTKEY       *dns.TKEY
		expectedAdditional []dns.RR
		expectedErr        error
	}{
		{
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
			algorithm:          GSS,
			mode:               TkeyModeGSS,
			lifetime:           3600,
			expectedTKEY:       goodTKEY,
			expectedAdditional: []dns.RR{},
			expectedErr:        nil,
		},
	}

	for _, c := range cases {
		tkey, additional, err := exchangeTKEY(&c.client, c.host, c.keyname, c.algorithm, c.mode, c.lifetime, c.input, c.extra, c.tsigname, c.tsigalgo, c.tsigmac)
		assert.Equal(t, c.expectedTKEY, tkey)
		assert.Equal(t, c.expectedAdditional, additional)
		assert.Equal(t, c.expectedErr, err)
	}
}
