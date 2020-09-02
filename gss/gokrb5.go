// +build !windows,!apcera

package gss

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/bodgit/tsig"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/miekg/dns"
)

type context struct {
	client *client.Client
	key    types.EncryptionKey
}

// GSS maps the TKEY name to the context that negotiated it as
// well as any other internal state.
type GSS struct {
	m   sync.RWMutex
	ctx map[string]context
}

// New performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func New() (*GSS, error) {

	c := &GSS{
		ctx: make(map[string]context),
	}

	return c, nil
}

// Close deletes any active contexts and unloads any underlying libraries as
// necessary.
// It returns any error that occurred.
func (c *GSS) Close() error {

	return c.close()
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

	c.m.RLock()
	defer c.m.RUnlock()

	ctx, ok := c.ctx[name]
	if !ok {
		return nil, dns.ErrSecret
	}

	token := gssapi.MICToken{
		Flags:     gssapi.MICTokenFlagAcceptorSubkey,
		SndSeqNum: 0,
		Payload:   msg,
	}

	if err := token.SetChecksum(ctx.key, keyusage.GSSAPI_INITIATOR_SIGN); err != nil {
		return nil, err
	}

	b, err := token.Marshal()
	if err != nil {
		return nil, err
	}

	return b, nil
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

	c.m.RLock()
	defer c.m.RUnlock()

	ctx, ok := c.ctx[name]
	if !ok {
		return dns.ErrSecret
	}

	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}

	var token gssapi.MICToken
	err = token.Unmarshal(mac, true)
	if err != nil {
		return err
	}
	token.Payload = stripped

	// This is the actual verification bit
	_, err = token.Verify(ctx.key, keyusage.GSSAPI_ACCEPTOR_SIGN)
	if err != nil {
		return err
	}

	return nil
}

func (c *GSS) negotiateContext(host string, cl *client.Client) (*string, *time.Time, error) {

	hostname, _ := tsig.SplitHostPort(host)

	keyname := generateTKEYName(hostname)

	tkt, key, err := cl.GetServiceTicket(generateSPN(hostname))
	if err != nil {
		return nil, nil, err
	}

	apreq, err := spnego.NewKRB5TokenAPREQ(cl, tkt, key, []int{gssapi.ContextFlagInteg}, []int{gssapi.ContextFlagMutual})
	if err != nil {
		return nil, nil, err
	}

	b, err := apreq.Marshal()
	if err != nil {
		return nil, nil, err
	}

	// We don't care about non-TKEY answers, no additional RR's to send, and no signing
	tkey, _, err := tsig.ExchangeTKEY(host, keyname, tsig.GSS, tsig.TkeyModeGSS, 3600, b, nil, nil, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	if tkey.Header().Name != keyname {
		return nil, nil, fmt.Errorf("TKEY name does not match")
	}

	b, err = hex.DecodeString(tkey.Key)
	if err != nil {
		return nil, nil, err
	}

	var aprep spnego.KRB5Token
	err = aprep.Unmarshal(b)
	if err != nil {
		return nil, nil, err
	}

	if aprep.IsKRBError() {
		return nil, nil, fmt.Errorf("received Kerberos error")
	}

	if !aprep.IsAPRep() {
		return nil, nil, fmt.Errorf("didn't receive an AP_REP")
	}

	b, err = crypto.DecryptEncPart(aprep.APRep.EncPart, key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, nil, err
	}

	var payload messages.EncAPRepPart
	err = payload.Unmarshal(b)
	if err != nil {
		return nil, nil, err
	}

	expiry := time.Unix(int64(tkey.Expiration), 0)

	c.m.Lock()
	defer c.m.Unlock()

	c.ctx[keyname] = context{
		client: cl,
		key:    payload.Subkey,
	}

	return &keyname, &expiry, nil
}

func loadCache() (*credentials.CCache, error) {

	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	path := "/tmp/krb5cc_" + u.Uid

	env := os.Getenv("KRB5CCNAME")
	if strings.HasPrefix(env, "FILE:") {
		path = strings.SplitN(env, ":", 2)[1]
	}

	cache, err := credentials.LoadCCache(path)
	if err != nil {
		return nil, err
	}

	return cache, nil
}

func loadConfig() (*config.Config, error) {

	path := os.Getenv("KRB5_CONFIG")
	_, err := os.Stat(path)
	if err != nil {

		// List of candidates to try
		try := []string{"/etc/krb5.conf"}

		for _, t := range try {
			_, err := os.Stat(t)
			if err == nil {
				path = t
				break
			}
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// NegotiateContext exchanges RFC 2930 TKEY records with the indicated DNS
// server to establish a security context using the current user.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *GSS) NegotiateContext(host string) (*string, *time.Time, error) {

	cache, err := loadCache()
	if err != nil {
		return nil, nil, err
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}

	cl, err := client.NewFromCCache(cache, cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return nil, nil, err
	}

	return c.negotiateContext(host, cl)
}

// NegotiateContextWithCredentials exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// credentials.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *GSS) NegotiateContextWithCredentials(host, domain, username, password string) (*string, *time.Time, error) {

	// Should I still initialise the credential cache?

	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}

	cl := client.NewWithPassword(username, domain, password, cfg, client.DisablePAFXFAST(true))

	err = cl.Login()
	if err != nil {
		return nil, nil, err
	}

	return c.negotiateContext(host, cl)
}

// NegotiateContextWithKeytab exchanges RFC 2930 TKEY records with the
// indicated DNS server to establish a security context using the provided
// keytab.
// It returns the negotiated TKEY name, expiration time, and any error that
// occurred.
func (c *GSS) NegotiateContextWithKeytab(host, domain, username, path string) (*string, *time.Time, error) {

	// Should I still initialise the credential cache?

	kt, err := keytab.Load(path)
	if err != nil {
		return nil, nil, err
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}

	cl := client.NewWithKeytab(username, domain, kt, cfg, client.DisablePAFXFAST(true))

	err = cl.Login()
	if err != nil {
		return nil, nil, err
	}

	return c.negotiateContext(host, cl)
}

// DeleteContext deletes the active security context associated with the given
// TKEY name.
// It returns any error that occurred.
func (c *GSS) DeleteContext(keyname *string) error {

	c.m.Lock()
	defer c.m.Unlock()

	ctx, ok := c.ctx[*keyname]
	if !ok {
		return fmt.Errorf("No such context")
	}

	ctx.client.Destroy()

	delete(c.ctx, *keyname)

	return nil
}
