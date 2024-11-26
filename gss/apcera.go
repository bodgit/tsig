//go:build !windows && apcera
// +build !windows,apcera

package gss

import (
	"encoding/hex"
	"net"
	"sync"
	"time"

	"github.com/bodgit/tsig"
	"github.com/bodgit/tsig/internal/util"
	"github.com/go-logr/logr"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/openshift/gssapi"
)

func generate(lib *gssapi.Lib, ctx *gssapi.CtxId, msg []byte) ([]byte, error) {
	message, err := lib.MakeBufferBytes(msg)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = multierror.Append(err, message.Release()).ErrorOrNil()
	}()

	token, err := ctx.GetMIC(gssapi.GSS_C_QOP_DEFAULT, message)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = multierror.Append(err, token.Release()).ErrorOrNil()
	}()

	return token.Bytes(), nil
}

func verify(lib *gssapi.Lib, ctx *gssapi.CtxId, stripped, mac []byte) error {
	message, err := lib.MakeBufferBytes(stripped)
	if err != nil {
		return err
	}

	defer func() {
		err = multierror.Append(err, message.Release()).ErrorOrNil()
	}()

	token, err := lib.MakeBufferBytes(mac)
	if err != nil {
		return err
	}

	defer func() {
		err = multierror.Append(err, token.Release()).ErrorOrNil()
	}()

	if _, err = ctx.VerifyMIC(message, token); err != nil {
		return err
	}

	return nil
}

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
func WithConfig[T Client](_ string) Option[T] {
	return unsupportedOption[T]
}

// NewClient performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func NewClient(dnsClient *dns.Client, options ...Option[Client]) (*Client, error) {
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

	for _, option := range options {
		if err := option(c); err != nil {
			return nil, multierror.Append(err, c.lib.Unload())
		}
	}

	return c, nil
}

// Close deletes any active contexts and unloads any underlying libraries as
// necessary.
// It returns any error that occurred.
func (c *Client) Close() error {
	return multierror.Append(c.close(), c.lib.Unload())
}

func (c *Client) generate(ctx *gssapi.CtxId, msg []byte) ([]byte, error) {
	return generate(c.lib, ctx, msg)
}

func (c *Client) verify(ctx *gssapi.CtxId, stripped, mac []byte) error {
	return verify(c.lib, ctx, stripped, mac)
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
		return "", time.Time{}, err
	}

	keyname, err = generateTKEYName(hostname)
	if err != nil {
		return "", time.Time{}, err
	}

	buffer, err := c.lib.MakeBufferString(generateSPN(hostname))
	if err != nil {
		return "", time.Time{}, err
	}

	defer func() {
		err = multierror.Append(err, buffer.Release()).ErrorOrNil()
	}()

	service, err := buffer.Name(c.lib.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		return "", time.Time{}, err
	}

	defer func() {
		err = multierror.Append(err, service.Release()).ErrorOrNil()
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
			err = multierror.Append(err, output.Release()).ErrorOrNil()
		}()

		if err != nil {
			if !c.lib.LastStatus.Major.ContinueNeeded() {
				return "", time.Time{}, err
			}
		} else {
			// There is no further token to send
			break
		}

		//nolint:lll
		tkey, _, err := util.ExchangeTKEY(c.client, host, keyname, tsig.GSS, util.TkeyModeGSS, 3600, output.Bytes(), nil, "", "")
		if err != nil {
			return "", time.Time{}, multierror.Append(err, ctx.DeleteSecContext())
		}

		if tkey.Header().Name != keyname {
			return "", time.Time{}, multierror.Append(errDoesNotMatch, ctx.DeleteSecContext())
		}

		key, err := hex.DecodeString(tkey.Key)
		if err != nil {
			return "", time.Time{}, multierror.Append(err, ctx.DeleteSecContext())
		}

		if input, err = c.lib.MakeBufferBytes(key); err != nil {
			return "", time.Time{}, multierror.Append(err, ctx.DeleteSecContext())
		}

		defer func() {
			err = multierror.Append(err, input.Release()).ErrorOrNil()
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

// Server maps the TKEY name to the context that negotiated it as
// well as any other internal state.
type Server struct {
	m      sync.RWMutex
	lib    *gssapi.Lib
	ctx    map[string]*gssapi.CtxId
	logger logr.Logger
}

// NewServer performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func NewServer(options ...Option[Server]) (*Server, error) {
	lib, err := gssapi.Load(nil)
	if err != nil {
		return nil, err
	}

	s := &Server{
		lib:    lib,
		ctx:    make(map[string]*gssapi.CtxId),
		logger: logr.Discard(),
	}

	for _, option := range options {
		if err := option(s); err != nil {
			return nil, multierror.Append(err, s.lib.Unload())
		}
	}

	return s, nil
}

// Close deletes any active contexts and unloads any underlying libraries as
// necessary.
// It returns any error that occurred.
func (s *Server) Close() error {
	return multierror.Append(s.close(true), s.lib.Unload()).ErrorOrNil()
}

func (s *Server) newContext() (*gssapi.CtxId, error) {
	//nolint:nilnil
	return nil, nil
}

//nolint:funlen
func (s *Server) update(ctx *gssapi.CtxId, input []byte) (*gssapi.CtxId, []byte, error) {
	/*var cred *gssapi.CredId

	// equivalent of GSSAPIStrictAcceptorCheck
	if s.strict { //nolint:nestif
		hostname, err := osHostname()
		if err != nil {
			return nil, "", false, err
		}

		buffer, err := s.lib.MakeBufferString("host@" + hostname)
		if err != nil {
			return nil, "", false, err
		}

		defer func() {
			err = multierror.Append(err, buffer.Release()).ErrorOrNil()
		}()

		service, err := buffer.Name(s.lib.GSS_C_NT_HOSTBASED_SERVICE)
		if err != nil {
			return nil, "", false, err
		}

		defer func() {
			err = multierror.Append(err, service.Release()).ErrorOrNil()
		}()

		oids, err := s.lib.MakeOIDSet(s.lib.GSS_MECH_KRB5)
		if err != nil {
			return nil, "", false, err
		}

		defer func() {
			err = multierror.Append(err, oids.Release()).ErrorOrNil()
		}()

		cred, _, _, err = s.lib.AcquireCred(service, gssapi.GSS_C_INDEFINITE, oids, gssapi.GSS_C_ACCEPT)
		if err != nil {
			return nil, "", false, err
		}

		defer func() {
			err = multierror.Append(err, cred.Release()).ErrorOrNil()
		}()
	} else {*/
	cred := s.lib.GSS_C_NO_CREDENTIAL
	//}

	token, err := s.lib.MakeBufferBytes(input)
	if err != nil {
		return nil, nil, err
	}

	defer func() {
		err = multierror.Append(err, token.Release()).ErrorOrNil()
	}()

	//nolint:dogsled
	nctx, _, _, output, _, _, _, err := s.lib.AcceptSecContext(ctx, cred, token, s.lib.GSS_C_NO_CHANNEL_BINDINGS)
	if err != nil && !s.lib.LastStatus.Major.ContinueNeeded() {
		return nil, nil, err
	}

	defer func() {
		err = multierror.Append(err, output.Release()).ErrorOrNil()
	}()

	return nctx, output.Bytes(), nil
}

func (s *Server) generate(ctx *gssapi.CtxId, msg []byte) ([]byte, error) {
	return generate(s.lib, ctx, msg)
}

func (s *Server) verify(ctx *gssapi.CtxId, stripped, mac []byte) error {
	return verify(s.lib, ctx, stripped, mac)
}

func (s *Server) established(ctx *gssapi.CtxId) (established bool, err error) {
	if ctx != nil {
		_, _, _, _, _, _, established, err = ctx.InquireContext()
	}

	return
}

func (s *Server) expired(ctx *gssapi.CtxId) (expired bool, err error) {
	if ctx != nil {
		var duration time.Duration
		_, _, duration, _, _, _, _, err = ctx.InquireContext()
		expired = duration <= 0
	}

	return
}

func (s *Server) delete(ctx *gssapi.CtxId) error {
	return ctx.DeleteSecContext()
}
