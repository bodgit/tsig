/*
Package dh implements RFC 2930 Diffie-Hellman key exchange functions.

Example client:

        import (
                "fmt"
                "net"
                "time"

                "github.com/bodgit/tsig/dh"
                "github.com/miekg/dns"
        )

        func main() {
                host := "ns.example.com"

                d, err := dh.New()
                if err != nil {
                        panic(err)
                }
                defer d.Close()

                // Negotiate a key with the chosen server
                keyname, mac, _, err := d.NegotiateKey(host, "tsig.example.com.", dns.HmacMD5, "k9uK5qsPfbBxvVuldwzYww==")
                if err != nil {
                        panic(err)
                }

                client := &dns.Client{
                        Net:        "tcp",
                        TsigSecret: map[string]string{*keyname: *mac},
                }

                // Use the DNS client as normal

                msg := new(dns.Msg)
                msg.SetUpdate(dns.Fqdn("example.com"))

                insert, err := dns.NewRR("test.example.com. 300 A 192.0.2.1")
                if err != nil {
                        panic(err)
                }
                msg.Insert([]dns.RR{insert})

                msg.SetTsig(*keyname, dns.HmacMD5, 300, time.Now().Unix())

                rr, _, err := client.Exchange(msg, net.JoinHostPort(host, "53"))
                if err != nil {
                        panic(err)
                }

                if rr.Rcode != dns.RcodeSuccess {
                        fmt.Printf("DNS error: %s (%d)\n", dns.RcodeToString[rr.Rcode], rr.Rcode)
                }

                // Revoke the key
                err = d.DeleteKey(keyname)
                if err != nil {
                        panic(err)
                }
        }
*/
package dh

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/bodgit/tsig"
	"github.com/enceve/crypto/dh"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
)

const (
	// RFC 2409, section 6.2
	modp1024 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
		"FFFFFFFFFFFFFFFF"
)

type context struct {
	host, algorithm, mac string
}

type dhkey struct {
	prime, generator, key []byte
}

// DH maps the TKEY name to the target host that negotiated it as
// well as any other internal state.
type DH struct {
	m   sync.Mutex
	ctx map[string]*context
}

func dhGroup(group int) (*dh.Group, error) {

	switch group {
	case 2:
		p, _ := new(big.Int).SetString(modp1024, 16)

		return &dh.Group{
			P: p,
			G: new(big.Int).SetInt64(2),
		}, nil
	default:
		return nil, fmt.Errorf("Unsupported DH group %v", group)
	}
}

// New performs any library initialization necessary.
// It returns a context handle for any further functions along with any error
// that occurred.
func New() (*DH, error) {

	c := &DH{
		ctx: make(map[string]*context),
	}

	return c, nil
}

// Close revokes any active keys and unloads any underlying libraries as
// necessary.
// It returns any error that occurred.
func (c *DH) Close() error {

	c.m.Lock()
	keys := make([]string, 0, len(c.ctx))
	for k := range c.ctx {
		keys = append(keys, k)
	}
	c.m.Unlock()

	var errs error
	for _, k := range keys {
		errs = multierror.Append(errs, c.DeleteKey(&k))
	}

	return errs
}

func readDHKey(raw []byte) (*dhkey, error) {

	var key dhkey

	r := bytes.NewBuffer(raw)

	var len uint16
	for _, f := range []*[]byte{&key.prime, &key.generator, &key.key} {
		err := binary.Read(r, binary.BigEndian, &len)
		if err != nil {
			return nil, err
		}

		*f = make([]byte, len)
		_, err = io.ReadFull(r, *f)
		if err != nil {
			return nil, err
		}
	}

	return &key, nil
}

func writeDHKey(key *dhkey) ([]byte, error) {

	w := new(bytes.Buffer)

	for _, f := range []*[]byte{&key.prime, &key.generator, &key.key} {
		len := uint16(len(*f))

		err := binary.Write(w, binary.BigEndian, len)
		if err != nil {
			return nil, err
		}

		_, err = w.Write(*f)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

func computeMD5(nonce, secret []byte) []byte {

	checksum := md5.Sum(append(nonce, secret...))

	return checksum[:]
}

func computeDHKey(ourNonce, peerNonce, secret []byte) []byte {

	operand := append(computeMD5(ourNonce, secret), computeMD5(peerNonce, secret)...)

	var result []byte
	if len(secret) > len(operand) {
		result = make([]byte, len(secret))
		copy(result, secret)
		for i := 0; i < len(operand); i++ {
			result[i] ^= operand[i]
		}
	} else {
		result = make([]byte, len(operand))
		copy(result, operand)
		for i := 0; i < len(secret); i++ {
			result[i] ^= secret[i]
		}
	}

	return result
}

// NegotiateKey exchanges RFC 2930 TKEY records with the indicated DNS
// server to establish a TSIG key for further using an existing TSIG key name,
// algorithm and MAC.
// It returns the negotiated TKEY name, MAC, expiry time, and any error that
// occurred.
func (c *DH) NegotiateKey(host, name, algorithm, mac string) (*string, *string, *time.Time, error) {

	keyname := "."

	g, err := dhGroup(2)
	if err != nil {
		return nil, nil, nil, err
	}

	ax, ay, err := g.GenerateKey(nil)
	if err != nil {
		return nil, nil, nil, err
	}

	adh := &dhkey{
		prime:     g.P.Bytes(),
		generator: g.G.Bytes(),
		key:       (*big.Int)(ay).Bytes(),
	}

	akey, err := writeDHKey(adh)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate our nonce
	an := make([]byte, 16) // FIXME I suspect it just is
	_, err = rand.Read(an)
	if err != nil {
		return nil, nil, nil, err
	}

	extra := make([]dns.RR, 1)

	extra[0] = &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   keyname,
			Rrtype: dns.TypeKEY,
			Class:  dns.ClassANY,
			Ttl:    0,
		},
		Flags:     512, // FIXME
		Protocol:  3,   // FIXME
		Algorithm: dns.DH,
		PublicKey: base64.StdEncoding.EncodeToString(akey),
	}

	tkey, keys, err := tsig.ExchangeTKEY(host, keyname, dns.HmacMD5, tsig.TkeyModeDH, 3600, an, extra, &name, &algorithm, &mac)
	if err != nil {
		return nil, nil, nil, err
	}

	var bkey []byte
	for _, k := range keys {
		switch key := k.(type) {
		case *dns.KEY:
			if key.Header().Name != keyname && key.Algorithm == dns.DH {
				bkey, err = base64.StdEncoding.DecodeString(key.PublicKey)
				if err != nil {
					return nil, nil, nil, err
				}
			}
		}
	}

	if bkey == nil {
		return nil, nil, nil, fmt.Errorf("No peer KEY record")
	}

	bdh, err := readDHKey(bkey)
	if err != nil {
		return nil, nil, nil, err
	}
	by := new(big.Int).SetBytes(bdh.key)

	err = g.Check(by)
	if err != nil {
		return nil, nil, nil, err
	}

	secret := g.ComputeSecret(ax, by).Bytes()

	// The peer nonce is in the TKEY response
	bn, err := hex.DecodeString(tkey.Key)
	if err != nil {
		return nil, nil, nil, err
	}

	lower := strings.ToLower(tkey.Header().Name)
	key := base64.StdEncoding.EncodeToString(computeDHKey(an, bn, secret))
	expiry := time.Unix(int64(tkey.Expiration), 0)

	c.m.Lock()
	defer c.m.Unlock()

	c.ctx[lower] = &context{
		host:      host,
		algorithm: dns.HmacMD5,
		mac:       key,
	}

	return &lower, &key, &expiry, nil
}

// DeleteKey revokes the active key associated with the given TKEY name.
// It returns any error that occurred.
func (c *DH) DeleteKey(keyname *string) error {

	c.m.Lock()
	defer c.m.Unlock()

	ctx, ok := c.ctx[*keyname]
	if !ok {
		return fmt.Errorf("No such context")
	}

	// Delete the key, signing the query with the key itself
	_, _, err := tsig.ExchangeTKEY(ctx.host, *keyname, ctx.algorithm, tsig.TkeyModeDelete, 0, nil, nil, keyname, &ctx.algorithm, &ctx.mac)
	if err != nil {
		return err
	}

	delete(c.ctx, *keyname)

	return nil
}
