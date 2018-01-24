// +build !windows

package tsig

import (
	"encoding/hex"
	"fmt"
	"github.com/apcera/gssapi"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"strings"
)

// Context maps the TKEY name to the context that negotiated it as
// well as any other internal state.
type Context struct {
	*gssapi.Lib // A handle to the underlying GSSAPI library.
	ctx         map[string]*gssapi.CtxId
}

// New performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func New() (*Context, error) {

	lib, err := gssapi.Load(nil)
	if err != nil {
		return nil, err
	}

	c := &Context{
		Lib: lib,
		ctx: make(map[string]*gssapi.CtxId),
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

	return multierror.Append(errs, c.Unload())
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

	message, err := c.MakeBufferBytes(msg)
	if err != nil {
		return nil, err
	}
	defer message.Release()

	token, err := ctx.GetMIC(gssapi.GSS_C_QOP_DEFAULT, message)
	if err != nil {
		return nil, err
	}
	defer token.Release()

	return token.Bytes(), nil
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

	// Turn the TSIG-stripped message bytes into a *gssapi.Buffer
	message, err := c.MakeBufferBytes(stripped)
	if err != nil {
		return err
	}
	defer message.Release()

	msgMAC, err := hex.DecodeString(tsig.MAC)
	if err != nil {
		return err
	}

	// Turn the TSIG MAC bytes into a *gssapi.Buffer
	token, err := c.MakeBufferBytes(msgMAC)
	if err != nil {
		return err
	}
	defer token.Release()

	// This is the actual verification bit
	_, err = ctx.VerifyMIC(message, token)
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

	buffer, err := c.MakeBufferString(generateSPN(host))
	if err != nil {
		return nil, err
	}
	defer buffer.Release()

	service, err := buffer.Name(c.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		return nil, err
	}

	var input *gssapi.Buffer
	var ctx *gssapi.CtxId

	for ok := true; ok; ok = c.LastStatus.Major.ContinueNeeded() {
		nctx, _, output, _, _, err := c.InitSecContext(
			c.GSS_C_NO_CREDENTIAL,
			ctx, // nil initially
			service,
			c.GSS_C_NO_OID,
			gssapi.GSS_C_DELEG_FLAG|gssapi.GSS_C_MUTUAL_FLAG|gssapi.GSS_C_REPLAY_FLAG|gssapi.GSS_C_SEQUENCE_FLAG|gssapi.GSS_C_INTEG_FLAG,
			0,
			c.GSS_C_NO_CHANNEL_BINDINGS,
			input)
		defer output.Release()
		ctx = nctx
		if err != nil {
			if !c.LastStatus.Major.ContinueNeeded() {
				return nil, err
			}
		} else {
			// There is no further token to send
			break
		}

		var errs error

		tkey, err := exchangeTKEY(host, keyname, output.Bytes())
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.DeleteSecContext())
			return nil, errs
		}

		input, err = c.MakeBufferBytes(tkey)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.DeleteSecContext())
			return nil, errs
		}
		defer input.Release()
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

	err := ctx.DeleteSecContext()
	if err != nil {
		return err
	}

	delete(c.ctx, *keyname)

	return nil
}
