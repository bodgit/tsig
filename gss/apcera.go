// +build !windows,apcera

package gss

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/bodgit/tsig"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/openshift/gssapi"
)

// GSS maps the TKEY name to the context that negotiated it as
// well as any other internal state.
type GSS struct {
	*gssapi.Lib // A handle to the underlying GSSAPI library.
	ctx         map[string]*gssapi.CtxId
}

// New performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func New() (*GSS, error) {

	lib, err := gssapi.Load(nil)
	if err != nil {
		return nil, err
	}

	c := &GSS{
		Lib: lib,
		ctx: make(map[string]*gssapi.CtxId),
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

	return multierror.Append(errs, c.Unload())
}

// GenerateGSS generates the TSIG MAC based on the established context.
// It is intended to be called as an algorithm-specific callback.
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

// VerifyGSS verifies the TSIG MAC based on the established context.
// It is intended to be called as an algorithm-specific callback.
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

	// Turn the TSIG-stripped message bytes into a *gssapi.Buffer
	message, err := c.MakeBufferBytes(stripped)
	if err != nil {
		return err
	}
	defer message.Release()

	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}

	// Turn the TSIG MAC bytes into a *gssapi.Buffer
	token, err := c.MakeBufferBytes(mac)
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
// server to establish a security context using the current user.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *GSS) NegotiateContext(host string) (*string, *time.Time, error) {

	hostname, _ := tsig.SplitHostPort(host)

	keyname := generateTKEYName(hostname)

	buffer, err := c.MakeBufferString(generateSPN(hostname))
	if err != nil {
		return nil, nil, err
	}
	defer buffer.Release()

	service, err := buffer.Name(c.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		return nil, nil, err
	}

	var input *gssapi.Buffer
	var ctx *gssapi.CtxId
	var tkey *dns.TKEY

	for ok := true; ok; ok = c.LastStatus.Major.ContinueNeeded() {
		nctx, _, output, _, _, err := c.InitSecContext(
			c.GSS_C_NO_CREDENTIAL,
			ctx, // nil initially
			service,
			c.GSS_C_NO_OID,
			gssapi.GSS_C_MUTUAL_FLAG|gssapi.GSS_C_REPLAY_FLAG|gssapi.GSS_C_INTEG_FLAG,
			0,
			c.GSS_C_NO_CHANNEL_BINDINGS,
			input)
		defer output.Release()
		ctx = nctx
		if err != nil {
			if !c.LastStatus.Major.ContinueNeeded() {
				return nil, nil, err
			}
		} else {
			// There is no further token to send
			break
		}

		var errs error

		// We don't care about non-TKEY answers, no additional RR's to send, and no signing
		tkey, _, err = tsig.ExchangeTKEY(host, keyname, tsig.GSS, tsig.TkeyModeGSS, 3600, output.Bytes(), nil, nil, nil, nil)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.DeleteSecContext())
			return nil, nil, errs
		}

		if tkey.Header().Name != keyname {
			errs = multierror.Append(errs, fmt.Errorf("TKEY name does not match"))
			errs = multierror.Append(errs, ctx.DeleteSecContext())
			return nil, nil, errs
		}

		key, err := hex.DecodeString(tkey.Key)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.DeleteSecContext())
			return nil, nil, errs
		}

		input, err = c.MakeBufferBytes(key)
		if err != nil {
			errs = multierror.Append(errs, err)
			errs = multierror.Append(errs, ctx.DeleteSecContext())
			return nil, nil, errs
		}
		defer input.Release()
	}

	expiry := time.Unix(int64(tkey.Expiration), 0)

	c.ctx[keyname] = ctx

	return &keyname, &expiry, nil
}

// NegotiateContextWithCredentials exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// credentials.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *GSS) NegotiateContextWithCredentials(host, domain, username, password string) (*string, *time.Time, error) {

	return nil, nil, fmt.Errorf("not supported")
}

// NegotiateContextWithKeytab exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// keytab.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *GSS) NegotiateContextWithKeytab(host, domain, username, path string) (*string, *time.Time, error) {

	return nil, nil, fmt.Errorf("not supported")
}

// DeleteContext deletes the active security context associated with the given
// TKEY name.
// It returns any error that occurred.
func (c *GSS) DeleteContext(keyname *string) error {

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
