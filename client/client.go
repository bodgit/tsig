package client

// A client implementation.

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsTimeout time.Duration = 2 * time.Second
)

// A Conn represents a connection to a DNS server.
type Conn struct {
	dns.Conn
	TsigAlgorithm  map[string]*TsigAlgorithm
	tsigRequestMAC string
}

// A Client defines parameters for a DNS client.
type Client struct {
	dns.Client
	TsigAlgorithm map[string]*TsigAlgorithm
	group         singleflight
}

func (c *Client) dialTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.DialTimeout != 0 {
		return c.DialTimeout
	}
	return dnsTimeout
}

func (c *Client) readTimeout() time.Duration {
	if c.ReadTimeout != 0 {
		return c.ReadTimeout
	}
	return dnsTimeout
}

func (c *Client) writeTimeout() time.Duration {
	if c.WriteTimeout != 0 {
		return c.WriteTimeout
	}
	return dnsTimeout
}

// Dial connects to the address on the named network.
func (c *Client) Dial(address string) (conn *Conn, err error) {
	// create a new dialer with the appropriate timeout
	var d net.Dialer
	if c.Dialer == nil {
		d = net.Dialer{}
	} else {
		d = net.Dialer(*c.Dialer)
	}
	d.Timeout = c.getTimeoutForRequest(c.writeTimeout())

	network := "udp"
	useTLS := false

	switch c.Net {
	case "tcp-tls":
		network = "tcp"
		useTLS = true
	case "tcp4-tls":
		network = "tcp4"
		useTLS = true
	case "tcp6-tls":
		network = "tcp6"
		useTLS = true
	default:
		if c.Net != "" {
			network = c.Net
		}
	}

	conn = new(Conn)
	if useTLS {
		conn.Conn.Conn, err = tls.DialWithDialer(&d, network, address, c.TLSConfig)
	} else {
		conn.Conn.Conn, err = d.Dial(network, address)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Exchange performs a synchronous query. It sends the message m to the address
// contained in a and waits for a reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	in, rtt, err := c.Exchange(message, "127.0.0.1:53")
//
// Exchange does not retry a failed query, nor will it fall back to TCP in
// case of truncation.
// It is up to the caller to create a message that allows for larger responses to be
// returned. Specifically this means adding an EDNS0 OPT RR that will advertise a larger
// buffer, see SetEdns0. Messages without an OPT RR will fallback to the historic limit
// of 512 bytes
// To specify a local address or a timeout, the caller has to set the `Client.Dialer`
// attribute appropriately
func (c *Client) Exchange(m *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error) {
	if !c.SingleInflight {
		return c.exchange(m, address)
	}

	t := "nop"
	if t1, ok := dns.TypeToString[m.Question[0].Qtype]; ok {
		t = t1
	}
	cl := "nop"
	if cl1, ok := dns.ClassToString[m.Question[0].Qclass]; ok {
		cl = cl1
	}
	r, rtt, err, shared := c.group.Do(m.Question[0].Name+t+cl, func() (*dns.Msg, time.Duration, error) {
		return c.exchange(m, address)
	})
	if r != nil && shared {
		r = r.Copy()
	}
	return r, rtt, err
}

func (c *Client) exchange(m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error) {
	var co *Conn

	co, err = c.Dial(a)

	if err != nil {
		return nil, 0, err
	}
	defer co.Close()

	opt := m.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}
	// Otherwise use the client's configured UDP size.
	if opt == nil && c.UDPSize >= dns.MinMsgSize {
		co.UDPSize = c.UDPSize
	}

	co.TsigSecret = c.TsigSecret
	co.TsigAlgorithm = c.TsigAlgorithm
	t := time.Now()
	// write with the appropriate write timeout
	co.SetWriteDeadline(t.Add(c.getTimeoutForRequest(c.writeTimeout())))
	if err = co.WriteMsg(m); err != nil {
		return nil, 0, err
	}

	co.SetReadDeadline(time.Now().Add(c.getTimeoutForRequest(c.readTimeout())))
	r, err = co.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = dns.ErrId
	}
	rtt = time.Since(t)
	return r, rtt, err
}

// ReadMsg reads a message from the connection co.
// If the received message contains a TSIG record the transaction signature
// is verified. This method always tries to return the message, however if an
// error is returned there are no guarantees that the returned message is a
// valid representation of the packet read.
func (co *Conn) ReadMsg() (*dns.Msg, error) {
	p, err := co.ReadMsgHeader(nil)
	if err != nil {
		return nil, err
	}

	m := new(dns.Msg)
	if err := m.Unpack(p); err != nil {
		// If an error was returned, we still want to allow the user to use
		// the message, but naively they can just check err if they don't want
		// to use an erroneous message
		return m, err
	}
	if t := m.IsTsig(); t != nil {
		if a, ok := co.TsigAlgorithm[t.Algorithm]; ok {
			if a.Verify != nil {
				if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
					return m, dns.ErrSecret
				}
				err = TsigVerifyByAlgorithm(p, a.Verify, t.Hdr.Name, co.TsigSecret[t.Hdr.Name], co.tsigRequestMAC, false)
			}
		} else {
			if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
				return m, dns.ErrSecret
			}
			// Need to work on the original message p, as that was used to calculate the tsig.
			err = TsigVerify(p, co.TsigSecret[t.Hdr.Name], co.tsigRequestMAC, false)
		}
	}
	return m, err
}

// WriteMsg sends a message through the connection co.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *dns.Msg) (err error) {
	var out []byte
	if t := m.IsTsig(); t != nil {
		mac := ""
		if a, ok := co.TsigAlgorithm[t.Algorithm]; ok {
			if a.Generate != nil {
				if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
					return dns.ErrSecret
				}
				out, mac, err = TsigGenerateByAlgorithm(m, a.Generate, t.Hdr.Name, co.TsigSecret[t.Hdr.Name], co.tsigRequestMAC, false)
			}
		} else {
			if _, ok := co.TsigSecret[t.Hdr.Name]; !ok {
				return dns.ErrSecret
			}
			out, mac, err = TsigGenerate(m, co.TsigSecret[t.Hdr.Name], co.tsigRequestMAC, false)
		}
		// Set for the next read, although only used in zone transfers
		co.tsigRequestMAC = mac
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	if _, err = co.Write(out); err != nil {
		return err
	}
	return nil
}

// Return the appropriate timeout for a specific request
func (c *Client) getTimeoutForRequest(timeout time.Duration) time.Duration {
	var requestTimeout time.Duration
	if c.Timeout != 0 {
		requestTimeout = c.Timeout
	} else {
		requestTimeout = timeout
	}
	// net.Dialer.Timeout has priority if smaller than the timeouts computed so
	// far
	if c.Dialer != nil && c.Dialer.Timeout != 0 {
		if c.Dialer.Timeout < requestTimeout {
			requestTimeout = c.Dialer.Timeout
		}
	}
	return requestTimeout
}
