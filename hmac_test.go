package tsig

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestHMACGenerate(t *testing.T) {
	tables := map[string]struct {
		provider HMAC
		msg      []byte
		tsig     *dns.TSIG
		b        []byte
		err      error
	}{
		"md5": {
			HMAC{"example.": "DRwIYZn6exnhof/mcV/aEQ=="},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacMD5,
			},
			[]byte{0xb, 0x78, 0x2f, 0xf6, 0xac, 0xb3, 0xf6, 0xbe, 0x52, 0xdb, 0x22, 0xc7, 0xce, 0x8, 0x11, 0x77},
			nil,
		},
		"sha1": {
			HMAC{"example.": "dZFRPtLqbQXGs7SdraTJJSGNSCU="},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacSHA1,
			},
			[]byte{0xb8, 0xb5, 0xdf, 0xd4, 0x27, 0x85, 0x7, 0x6f, 0x2f, 0x3a, 0xa9, 0xc6, 0xf9, 0xfe, 0x98, 0x68, 0xc5, 0xbd, 0x9b, 0x7a},
			nil,
		},
		"sha224": {
			HMAC{"example.": "NaDGqfyc2/Fc0muCPB78CyGPlveTursOxrPVVQ=="},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacSHA224,
			},
			[]byte{0xfc, 0x1c, 0xf5, 0xd9, 0x5e, 0x1f, 0xb0, 0xd5, 0xad, 0x2d, 0x53, 0x5a, 0x69, 0x2e, 0x47, 0x5c, 0x3a, 0xa8, 0xed, 0x52, 0x41, 0x4c, 0x71, 0x7d, 0xd9, 0x87, 0x3a, 0xcb},
			nil,
		},
		"sha256": {
			HMAC{"example.": "BduxMlVUsrEhdgfOLKSLhNE4D3qzDx7dwyRjt7+BDNE="},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacSHA256,
			},
			[]byte{0xdc, 0x76, 0x7, 0x57, 0xa5, 0x92, 0x1, 0x55, 0x1d, 0x57, 0xdc, 0xaf, 0x43, 0x6a, 0x45, 0xdc, 0xec, 0xa9, 0xb7, 0x1b, 0x63, 0x37, 0x63, 0x90, 0x4b, 0x63, 0x5d, 0xc3, 0x96, 0xeb, 0x42, 0xd6},
			nil,
		},
		"sha384": {
			HMAC{"example.": "xqbc2K8kfLDw3yNOOw9kloxrLPX0ILoGK4sxZwVOgDnGzcp9DZu5nDQMZBofAIYf"},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacSHA384,
			},
			[]byte{0x21, 0x29, 0xfa, 0x1c, 0x10, 0x4b, 0x12, 0x81, 0x95, 0x98, 0x36, 0x5a, 0x92, 0x88, 0x1e, 0x5a, 0x26, 0x76, 0x28, 0x5a, 0xc, 0xe7, 0x53, 0xa5, 0x3c, 0xb6, 0xad, 0x12, 0xc2, 0x7b, 0xb9, 0xd5, 0x88, 0x2f, 0x24, 0xae, 0x39, 0x54, 0xd5, 0xbb, 0x95, 0x7f, 0x30, 0x1c, 0x42, 0x61, 0x22, 0xc5},
			nil,
		},
		"sha512": {
			HMAC{"example.": "WCltYAUyQQjslkIIOXnvJkC3bSlCPEsl6gYEzkIyUbnXbmJZA5PTgSL8fLlwfDKYJl/SiFMTOzQxWvH7AmUvSw=="},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacSHA512,
			},
			[]byte{0xdb, 0x3e, 0x97, 0x64, 0x17, 0x8a, 0x93, 0x60, 0x19, 0x6b, 0x80, 0xe4, 0xac, 0xba, 0xbd, 0xb7, 0x1e, 0xe9, 0xb4, 0xf6, 0xc3, 0xe, 0xc0, 0x2c, 0xcd, 0xcf, 0xf3, 0xff, 0x29, 0x8c, 0x3, 0xfa, 0x4b, 0x58, 0xf0, 0xfe, 0xaa, 0x15, 0x6e, 0x77, 0x8f, 0x98, 0x65, 0x72, 0x3c, 0x94, 0x4e, 0x3f, 0xc9, 0xdc, 0x4c, 0x88, 0x7c, 0x4d, 0xfb, 0x23, 0x8a, 0xad, 0xe5, 0x4f, 0xcc, 0x73, 0x50, 0x59},
			nil,
		},
		"algorithm": {
			HMAC{"example.": ""},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: GSS,
			},
			nil,
			dns.ErrKeyAlg,
		},
		"secret": {
			HMAC{},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacMD5,
			},
			nil,
			dns.ErrSecret,
		},
		"garbage": {
			HMAC{"example.": "garbage"},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacMD5,
			},
			nil,
			base64.CorruptInputError(4),
		},
	}

	for name, table := range tables {
		t.Run(name, func(t *testing.T) {
			b, err := table.provider.Generate(table.msg, table.tsig)
			assert.Equal(t, table.b, b)
			assert.Equal(t, table.err, err)
		})
	}
}

func TestHMACVerify(t *testing.T) {
	tables := map[string]struct {
		provider HMAC
		msg      []byte
		tsig     *dns.TSIG
		err      error
	}{
		"md5": {
			HMAC{"example.": "DRwIYZn6exnhof/mcV/aEQ=="},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacMD5,
				MAC:       hex.EncodeToString([]byte{0xb, 0x78, 0x2f, 0xf6, 0xac, 0xb3, 0xf6, 0xbe, 0x52, 0xdb, 0x22, 0xc7, 0xce, 0x8, 0x11, 0x77}),
			},
			nil,
		},
		"algorithm": {
			HMAC{"example.": "DRwIYZn6exnhof/mcV/aEQ=="},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: GSS,
				MAC:       "",
			},
			dns.ErrKeyAlg,
		},
		"garbage": {
			HMAC{"example.": "DRwIYZn6exnhof/mcV/aEQ=="},
			[]byte("message"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacMD5,
				MAC:       "garbage",
			},
			hex.InvalidByteError(0x67),
		},
		"signature": {
			HMAC{"example.": "DRwIYZn6exnhof/mcV/aEQ=="},
			[]byte("different"),
			&dns.TSIG{
				Hdr: dns.RR_Header{
					Name: "example.",
				},
				Algorithm: dns.HmacMD5,
				MAC:       hex.EncodeToString([]byte{0xb, 0x78, 0x2f, 0xf6, 0xac, 0xb3, 0xf6, 0xbe, 0x52, 0xdb, 0x22, 0xc7, 0xce, 0x8, 0x11, 0x77}),
			},
			dns.ErrSig,
		},
	}

	for name, table := range tables {
		t.Run(name, func(t *testing.T) {
			err := table.provider.Verify(table.msg, table.tsig)
			assert.Equal(t, table.err, err)
		})
	}
}
