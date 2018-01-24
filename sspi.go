// +build windows

package tsig

import (
	"encoding/hex"
	"fmt"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"strings"
)

// Context maps the TKEY name to the context that negotiated it as
// well as any other internal state.
type Context struct {
	ctx map[string]*negotiate.ClientContext
}

// New performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func New() (*Context, error) {

	c := &Context{
		ctx: make(map[string]*negotiate.ClientContext),
	}

	return c, nil
}

// Close deletes any active contexts and unloads any underlying libraries as
// necessary.
// It returns any error that occurred.
func (c *Context) Close() error {

	var errs error
	for k := range c.ctx {
		errs = multierror.Append(errs, c.DeleteContext(&k))
	}

	return errs
}

// GenerateGssTsig generates the TSIG MAC based on the established context.
// It is not intended to be called directly but by the github/miekg/dns
// package as an algorithm-specific callback.
// It is called with the bytes of the DNS message, the algorithm name, the
// TSIG name (which is the negotiated TKEY for this context) and the secret
// (which is ignored).
// It returns the bytes for the TSIG MAC and any error that occurred.
func (c *Context) GenerateGssTsig(msg []byte, algorithm, name, secret string) ([]byte, error) {

	if strings.ToLower(algorithm) != GssTsig {
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

// VerifyGssTsig verifies the TSIG MAC based on the established context.
// It is not intended to be called directly but by the github.com/miekg/dns
// package as an algorithm-specific callback.
// It is called with the bytes of the DNS message, the TSIG record, the TSIG
// name (which is the negotiated TKEY for this context) and the secret (which
// is ignored).
// It returns any error that occurred.
func (c *Context) VerifyGssTsig(stripped []byte, tsig *dns.TSIG, name, secret string) error {

	if strings.ToLower(tsig.Algorithm) != GssTsig {
		return dns.ErrKeyAlg
	}

	ctx, ok := c.ctx[name]
	if !ok {
		return dns.ErrSecret
	}

	token, err := hex.DecodeString(tsig.MAC)
	if err != nil {
		return err
	}

	_, err = ctx.VerifySignature(stripped, token, 0)
	if err != nil {
		return err
	}

	return nil
}

// NegotiateContext exchanges RFC 2930 TKEY records with the indicated DNS
// server to establish a security context for further use.
// It returns the negotiated TKEY name and any error that occurred.
func (c *Context) NegotiateContext(host string) (*string, error) {

	keyname := generateTKEYName(host)

	creds, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}
	defer creds.Release()

	ctx, output, err := negotiate.NewClientContext(creds, generateSPN(host))
	if err != nil {
		return nil, err
	}

	var completed bool

	for ok := false; !ok; ok = completed {

		var errs error

		input, err := exchangeTKEY(host, keyname, output)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.Release())
			return nil, errs
		}

		completed, output, err = ctx.Update(input)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.Release())
			return nil, errs
		}
	}

	// nsupdate(1) intentionally skips the TSIG on the TKEY response

	c.ctx[keyname] = ctx

	return &keyname, nil
}

// DeleteContext deletes the active security context associated with the given
// TKEY name.
// It returns any error that occurred.
func (c *Context) DeleteContext(keyname *string) error {

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
