// +build !windows

package tsig

import (
	"encoding/hex"
	"fmt"
	"github.com/apcera/gssapi"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"strings"
	"time"
)

type Context struct {
	*gssapi.Lib
	ctx map[string]*gssapi.CtxId
}

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

func (c *Context) Close() error {

	// FIXME possibly need to loop through and delete any active contexts

	c.ctx = make(map[string]*gssapi.CtxId)

	return c.Unload()
}

func (c *Context) TsigGenerateGssapi(msg []byte, algorithm, name, secret string) ([]byte, error) {

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

func (c *Context) TsigVerifyGssapi(stripped []byte, tsig *dns.TSIG, name, secret string) error {

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

func (c *Context) NegotiateGssapiCtx(host string) (*string, error) {

	seed := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(seed)

	keyname := dns.Fqdn(fmt.Sprintf("%d.sig-%s", rng.Int31(), host))

	buffer, err := c.MakeBufferString(fmt.Sprintf("DNS/%s", host))
	if err != nil {
		return nil, err
	}
	defer buffer.Release()

	service, err := buffer.Name(c.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		return nil, err
	}

	var input *gssapi.Buffer = c.GSS_C_NO_BUFFER
	var ctx *gssapi.CtxId = c.GSS_C_NO_CONTEXT
	var rr *dns.Msg = nil

	client := &dns.Client{
		Net:           "tcp",
		TsigAlgorithm: map[string]*dns.TsigAlgorithm{GssTsig: {nil, nil}},
		TsigSecret:    map[string]string{keyname: ""},
	}

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
		Question: make([]dns.Question, 1),
		Extra:    make([]dns.RR, 1),
	}

	m.Question[0] = dns.Question{
		Name:   keyname,
		Qtype:  dns.TypeTKEY,
		Qclass: dns.ClassANY,
	}

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

		now := time.Now().Unix()
		m.Extra[0] = &dns.TKEY{
			Hdr: dns.RR_Header{
				Name:   keyname,
				Rrtype: dns.TypeTKEY,
				Class:  dns.ClassANY,
				Ttl:    0,
			},
			Algorithm:  GssTsig,
			Mode:       3,
			Inception:  uint32(now),
			Expiration: uint32(now),
			KeySize:    uint16(output.Length()),
			Key:        hex.EncodeToString(output.Bytes()),
		}

		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, err
		}

		// FIXME Try all resolved addresses in case of failure
		rr, _, err = client.Exchange(m, net.JoinHostPort(addrs[0], "53"))
		if err != nil {
			return nil, err
		}

		if rr.Rcode != dns.RcodeSuccess {
			err = ctx.DeleteSecContext()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("DNS error: %s (%d)", dns.RcodeToString[rr.Rcode], rr.Rcode)
		}

		// FIXME Perform wellformed-ness checks

		for _, ans := range rr.Answer {
			switch t := ans.(type) {
			case *dns.TKEY:
				if t.Error != 0 {
					err = ctx.DeleteSecContext()
					if err != nil {
						return nil, err
					}
					return nil, fmt.Errorf("TKEY error: %d", t.Error)
				}

				b, err := hex.DecodeString(t.Key)
				if err != nil {
					return nil, err
				}

				input, err = c.MakeBufferBytes(b)
				defer input.Release()
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// nsupdate(1) intentionally skips the TSIG on the TKEY response

	c.ctx[keyname] = ctx

	return &keyname, nil
}

func (c *Context) DeleteGssapiCtx(keyname *string) error {

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
