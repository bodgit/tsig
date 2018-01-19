// +build windows

package tsig

import (
	"encoding/hex"
	"fmt"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/miekg/dns"
	"net"
	"strings"
)

type Context struct {
	ctx map[string]*negotiate.ClientContext
}

func New() (*Context, error) {

	c := &Context{
		ctx: make(map[string]*negotiate.ClientContext),
	}

	return c, nil
}

func (c *Context) Close() error {

	for k := range c.ctx {
		err := c.DeleteContext(&k)
		if err != nil {
			return err
		}
	}

	return nil
}

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

	client, msg := bootstrapDNSClient(keyname)

	var completed bool
	var input []byte

	for ok := false; !ok; ok = completed {

		msg.Id = dns.Id()
		msg.Extra[0] = generateTKEY(keyname, output)

		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, err
		}

		// FIXME Try all resolved addresses in case of failure
		rr, _, err := client.Exchange(msg, net.JoinHostPort(addrs[0], "53"))
		if err != nil {
			return nil, err
		}

		if rr.Rcode != dns.RcodeSuccess {
			err = ctx.Release()
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
					err = ctx.Release()
					if err != nil {
						return nil, err
					}
					return nil, fmt.Errorf("TKEY error: %d", t.Error)
				}

				input, err = hex.DecodeString(t.Key)
				if err != nil {
					return nil, err
				}
			}
		}

		completed, output, err = ctx.Update(input)
		if err != nil {
			err = ctx.Release()
			if err != nil {
				return nil, err
			}
			return nil, err
		}
	}

	// nsupdate(1) intentionally skips the TSIG on the TKEY response

	c.ctx[keyname] = ctx

	return &keyname, nil
}

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
