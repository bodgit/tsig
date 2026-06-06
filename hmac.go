package tsig

import (
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"

	dnsv1 "github.com/miekg/dns"
)

// HMAC implements the standard HMAC TSIG methods using the [dnsv1.TsigProvider]
// interface. It holds a map of TSIG key names to base64-encoded secrets. The
// key names should be in canonical form, see [dnsv1.CanonicalName].
type HMAC map[string]string

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]

	return
}

// Generate generates the TSIG MAC using the HMAC algorithm indicated by
// t.Algorithm using h[t.Hdr.Name] as the key.
// It returns the bytes for the TSIG MAC and any error that occurred.
func (h HMAC) Generate(msg []byte, t *dnsv1.TSIG) ([]byte, error) {
	var f func() hash.Hash

	switch dnsv1.CanonicalName(t.Algorithm) {
	case dnsv1.HmacMD5:
		f = md5.New
	case dnsv1.HmacSHA1:
		f = sha1.New
	case dnsv1.HmacSHA224:
		f = sha256.New224
	case dnsv1.HmacSHA256:
		f = sha256.New
	case dnsv1.HmacSHA384:
		f = sha512.New384
	case dnsv1.HmacSHA512:
		f = sha512.New
	default:
		return nil, dnsv1.ErrKeyAlg
	}

	secret, ok := h[t.Hdr.Name]
	if !ok {
		return nil, dnsv1.ErrSecret
	}

	rawsecret, err := fromBase64([]byte(secret))
	if err != nil {
		return nil, err
	}

	m := hmac.New(f, rawsecret)
	m.Write(msg)

	return m.Sum(nil), nil
}

// Verify verifies the TSIG MAC using the HMAC algorithm indicated by
// t.Algorithm using h[t.Hdr.Name] as the key.
// It returns any error that occurred.
func (h HMAC) Verify(msg []byte, t *dnsv1.TSIG) error {
	b, err := h.Generate(msg, t)
	if err != nil {
		return err
	}

	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}

	if !hmac.Equal(b, mac) {
		return dnsv1.ErrSig
	}

	return nil
}
