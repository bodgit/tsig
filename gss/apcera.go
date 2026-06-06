//go:build !windows && apcera
// +build !windows,apcera

package gss

import (
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/bodgit/tsig"
	"github.com/bodgit/tsig/internal/util"
	"github.com/go-logr/logr"
	"github.com/miekg/dns"
	"github.com/openshift/gssapi"
)

// Client maps the TKEY name to the context that negotiated it as
// well as any other internal state.
type Client struct {
	m      sync.RWMutex
	lib    *gssapi.Lib
	client *dns.Client
	ctx    map[string]*gssapi.CtxId
	logger logr.Logger
}

// WithConfig sets the Kerberos configuration used.
func WithConfig(_ string) func(*Client) error {
	return func(c *Client) error {
		return errNotSupported
	}
}

// NewClient performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func NewClient(dnsClient *dns.Client, options ...func(*Client) error) (*Client, error) {
	client, err := util.CopyDNSClient(dnsClient)
	if err != nil {
		return nil, err
	}

	client.TsigProvider = new(gssNoVerify)

	lib, err := gssapi.Load(nil)
	if err != nil {
		return nil, err
	}

	c := &Client{
		lib:    lib,
		client: client,
		ctx:    make(map[string]*gssapi.CtxId),
		logger: logr.Discard(),
	}

	if err := c.setOption(options...); err != nil {
		return nil, errors.Join(err, c.lib.Unload())
	}

	return c, nil
}

// Close deletes any active contexts and unloads any underlying libraries as
// necessary.
// It returns any error that occurred.
func (c *Client) Close() error {
	return errors.Join(c.close(), c.lib.Unload())
}

func (c *Client) generate(ctx *gssapi.CtxId, msg []byte) (b []byte, err error) {
	message, err := c.lib.MakeBufferBytes(msg)
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, message.Release())
	}()

	token, err := ctx.GetMIC(gssapi.GSS_C_QOP_DEFAULT, message)
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, token.Release())
	}()

	b = token.Bytes()

	return
}

func (c *Client) verify(ctx *gssapi.CtxId, stripped, mac []byte) (err error) {
	// Turn the TSIG-stripped message bytes into a *gssapi.Buffer
	message, err := c.lib.MakeBufferBytes(stripped)
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, message.Release())
	}()

	// Turn the TSIG MAC bytes into a *gssapi.Buffer
	token, err := c.lib.MakeBufferBytes(mac)
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, token.Release())
	}()

	// This is the actual verification bit
	_, err = ctx.VerifyMIC(message, token)

	return
}

// NegotiateContext exchanges RFC 2930 TKEY records with the indicated DNS
// server to establish a security context using the current user.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
//
//nolint:cyclop,funlen
func (c *Client) NegotiateContext(host string) (keyname string, expiry time.Time, err error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return
	}

	keyname, err = generateTKEYName(hostname)
	if err != nil {
		return
	}

	buffer, err := c.lib.MakeBufferString(generateSPN(hostname))
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, buffer.Release())
	}()

	service, err := buffer.Name(c.lib.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, service.Release())
	}()

	var (
		input *gssapi.Buffer
		ctx   *gssapi.CtxId
	)

	for ok := true; ok; ok = c.lib.LastStatus.Major.ContinueNeeded() {
		nctx, _, output, _, duration, err := c.lib.InitSecContext(
			c.lib.GSS_C_NO_CREDENTIAL,
			ctx, // nil initially
			service,
			c.lib.GSS_C_NO_OID,
			gssapi.GSS_C_MUTUAL_FLAG|gssapi.GSS_C_REPLAY_FLAG|gssapi.GSS_C_INTEG_FLAG,
			0,
			c.lib.GSS_C_NO_CHANNEL_BINDINGS,
			input)

		ctx, expiry = nctx, time.Now().UTC().Add(duration)

		defer func() {
			err = errors.Join(err, output.Release())
		}()

		if err != nil {
			if !c.lib.LastStatus.Major.ContinueNeeded() {
				return
			}
		} else {
			// There is no further token to send
			break
		}

		//nolint:lll
		tkey, _, err := util.ExchangeTKEY(c.client, host, keyname, tsig.GSS, util.TkeyModeGSS, 3600, output.Bytes(), nil, "", "")
		if err != nil {
			err = errors.Join(err, ctx.DeleteSecContext())

			return
		}

		if tkey.Header().Name != keyname {
			err = errors.Join(errDoesNotMatch, ctx.DeleteSecContext())

			return
		}

		key, err := hex.DecodeString(tkey.Key)
		if err != nil {
			err = errors.Join(err, ctx.DeleteSecContext())

			return
		}

		if input, err = c.lib.MakeBufferBytes(key); err != nil {
			err = errors.Join(err, ctx.DeleteSecContext())

			return
		}

		defer func() {
			err = errors.Join(err, input.Release())
		}()
	}

	c.m.Lock()
	defer c.m.Unlock()

	c.ctx[keyname] = ctx

	return keyname, expiry, nil
}

// NegotiateContextWithCredentials exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// credentials.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *Client) NegotiateContextWithCredentials(_, _, _, _ string) (string, time.Time, error) {
	return "", time.Time{}, errNotSupported
}

// NegotiateContextWithKeytab exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// keytab.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *Client) NegotiateContextWithKeytab(_, _, _, _ string) (string, time.Time, error) {
	return "", time.Time{}, errNotSupported
}

// DeleteContext deletes the active security context associated with the given
// TKEY name.
// It returns any error that occurred.
func (c *Client) DeleteContext(keyname string) error {
	c.m.Lock()
	defer c.m.Unlock()

	ctx, ok := c.ctx[keyname]
	if !ok {
		return errNoSuchContext
	}

	if err := ctx.DeleteSecContext(); err != nil {
		return err
	}

	delete(c.ctx, keyname)

	return nil
}
