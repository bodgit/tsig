// +build windows

package gss

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/bodgit/tsig"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
)

// GSS maps the TKEY name to the context that negotiated it as
// well as any other internal state.
type GSS struct {
	ctx map[string]*negotiate.ClientContext
}

// New performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func New() (*GSS, error) {

	c := &GSS{
		ctx: make(map[string]*negotiate.ClientContext),
	}

	return c, nil
}

// Close deletes any active contexts and unloads any underlying libraries as
// necessary.
// It returns any error that occurred.
func (c *GSS) Close() error {

	var errs error
	for k := range c.ctx {
		errs = multierror.Append(errs, c.DeleteContext(&k))
	}

	return errs
}

// GenerateGSS generates the TSIG MAC based on the established context.
// It is not intended to be called directly but by the github/miekg/dns
// package as an algorithm-specific callback.
// It is called with the bytes of the DNS message, the algorithm name, the
// TSIG name (which is the negotiated TKEY for this context) and the secret
// (which is ignored).
// It returns the bytes for the TSIG MAC and any error that occurred.
func (c *GSS) GenerateGSS(msg []byte, algorithm, name, secret string) ([]byte, error) {

	if strings.ToLower(algorithm) != tsig.GSS {
		return nil, dns.ErrKeyAlg
	}

	ctx, ok := c.ctx[name]
	if !ok {
		return nil, dns.ErrSecret
	}

	token, err := ctx.MakeSignature(msg, 0, 0)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// VerifyGSS verifies the TSIG MAC based on the established context.
// It is not intended to be called directly but by the github.com/miekg/dns
// package as an algorithm-specific callback.
// It is called with the bytes of the DNS message, the TSIG record, the TSIG
// name (which is the negotiated TKEY for this context) and the secret (which
// is ignored).
// It returns any error that occurred.
func (c *GSS) VerifyGSS(stripped []byte, t *dns.TSIG, name, secret string) error {

	if strings.ToLower(t.Algorithm) != tsig.GSS {
		return dns.ErrKeyAlg
	}

	ctx, ok := c.ctx[name]
	if !ok {
		return dns.ErrSecret
	}

	token, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}

	_, err = ctx.VerifySignature(stripped, token, 0)
	if err != nil {
		return err
	}

	return nil
}

func (c *GSS) negotiateContext(host string, creds *sspi.Credentials) (*string, *time.Time, error) {

	keyname := generateTKEYName(host)

	ctx, output, err := negotiate.NewClientContext(creds, generateSPN(host))
	if err != nil {
		return nil, nil, err
	}

	var completed bool
	var tkey *dns.TKEY

	for ok := false; !ok; ok = completed {

		var errs error

		// We don't care about non-TKEY answers, no additional RR's to send, and no signing
		tkey, _, err = tsig.ExchangeTKEY(host, keyname, tsig.GSS, tsig.TkeyModeGSS, 3600, output, nil, nil, nil, nil)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.Release())
			return nil, nil, errs
		}

		if tkey.Header().Name != keyname {
			errs = multierror.Append(errs, fmt.Errorf("TKEY name does not match"))
			errs = multierror.Append(errs, ctx.Release())
			return nil, nil, errs
		}

		input, err := hex.DecodeString(tkey.Key)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.Release())
			return nil, nil, errs
		}

		completed, output, err = ctx.Update(input)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.Release())
			return nil, nil, errs
		}
	}

	expiry := time.Unix(int64(tkey.Expiration), 0)

	c.ctx[keyname] = ctx

	return &keyname, &expiry, nil
}

// NegotiateContext exchanges RFC 2930 TKEY records with the indicated DNS
// server to establish a security context using the current user.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *GSS) NegotiateContext(host string) (*string, *time.Time, error) {

	creds, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, nil, err
	}
	defer creds.Release()

	return c.negotiateContext(host, creds)
}

// NegotiateContextWithCredentials exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// credentials.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *GSS) NegotiateContextWithCredentials(host, domain, username, password string) (*string, *time.Time, error) {

	creds, err := negotiate.AcquireUserCredentials(domain, username, password)
	if err != nil {
		return nil, nil, err
	}
	defer creds.Release()

	return c.negotiateContext(host, creds)
}

// DeleteContext deletes the active security context associated with the given
// TKEY name.
// It returns any error that occurred.
func (c *GSS) DeleteContext(keyname *string) error {

	ctx, ok := c.ctx[*keyname]
	if !ok {
		return fmt.Errorf("No such context")
	}

	err := ctx.Release()
	if err != nil {
		return err
	}

	delete(c.ctx, *keyname)

	return nil
}
