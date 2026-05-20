package gss

import (
	"encoding/hex"
	"time"

	"github.com/bodgit/tsig"
	"github.com/bodgit/tsig/internal/util"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
)

var (
	_ dns.TsigProvider = new(Server)
	_ dns.Handler      = new(Server)
)

func (s *Server) close(all bool) error {
	s.m.Lock()
	defer s.m.Unlock()

	var errs *multierror.Error

	for keyname, ctx := range s.ctx {
		switch {
		case !all:
			expired, err := s.expired(ctx)
			if err != nil {
				errs = multierror.Append(errs, err)

				continue
			}

			if !expired {
				continue
			}

			fallthrough
		default:
			if err := s.delete(ctx); err != nil {
				errs = multierror.Append(errs, err)
			}

			delete(s.ctx, keyname)
		}
	}

	return errs.ErrorOrNil()
}

// Generate generates the TSIG MAC based on the established context.
// It is called with the bytes of the DNS message, and the partial TSIG
// record containing the algorithm and name which is the negotiated TKEY
// for this context.
// It returns the bytes for the TSIG MAC and any error that occurred.
func (s *Server) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	if err := s.close(false); err != nil {
		return nil, err
	}

	if dns.CanonicalName(t.Algorithm) != tsig.GSS {
		return nil, dns.ErrKeyAlg
	}

	s.m.RLock()
	defer s.m.RUnlock()

	ctx, ok := s.ctx[t.Hdr.Name]
	if !ok { // || !ctx.Established() {
		return nil, dns.ErrSecret
	}

	return s.generate(ctx, msg)
}

// Verify verifies the TSIG MAC based on the established context.
// It is called with the bytes of the DNS message, and the TSIG record
// containing the algorithm, MAC, and name which is the negotiated TKEY
// for this context.
// It returns any error that occurred.
func (s *Server) Verify(stripped []byte, t *dns.TSIG) error {
	if err := s.close(false); err != nil {
		return err
	}

	if dns.CanonicalName(t.Algorithm) != tsig.GSS {
		return dns.ErrKeyAlg
	}

	s.m.RLock()
	defer s.m.RUnlock()

	ctx, ok := s.ctx[t.Hdr.Name]
	if !ok {
		return dns.ErrSecret
	}

	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}

	return s.verify(ctx, stripped, mac)
}

func extractTKEY(r *dns.Msg) *dns.TKEY {
	if len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeTKEY || r.Question[0].Qclass != dns.ClassANY {
		return nil
	}

	if len(r.Extra) != 1 {
		return nil
	}

	tkey, ok := r.Extra[0].(*dns.TKEY)
	if !ok {
		return nil
	}

	if tkey.Hdr.Name != r.Question[0].Name || tkey.Hdr.Rrtype != dns.TypeTKEY ||
		tkey.Hdr.Class != dns.ClassANY || tkey.Hdr.Ttl != 0 {
		return nil
	}

	return tkey
}

// ServeDNS satisfies the dns.Handler interface. It only handles queries for
// TKEY records and will refuse anything else.
//
//nolint:cyclop,funlen
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.logger.Info("incoming", "request", r.String())

	m := new(dns.Msg)
	defer func() {
		if err := w.WriteMsg(m); err != nil {
			s.logger.Error(err, "write error")
		}
	}()

	if err := s.close(false); err != nil {
		m.SetRcode(r, dns.RcodeServerFailure)

		return
	}

	tkey := extractTKEY(r)
	if tkey == nil {
		m.SetRcode(r, dns.RcodeRefused)

		return
	}

	keyname := tkey.Hdr.Name

	input, err := hex.DecodeString(tkey.Key)
	if err != nil {
		s.logger.Error(err, "unable to decode key")
		m.SetRcode(r, dns.RcodeFormatError)

		return
	}

	m.SetReply(r)

	rr := &dns.TKEY{
		Hdr: dns.RR_Header{
			Name:   keyname,
			Rrtype: dns.TypeTKEY,
			Class:  dns.ClassANY,
		},
		Algorithm:  tkey.Algorithm,
		Mode:       tkey.Mode,
		Inception:  tkey.Inception,
		Expiration: tkey.Expiration,
		KeySize:    tkey.KeySize,
		Key:        tkey.Key,
	}
	m.Answer = append(m.Answer, rr)

	if tkey.Algorithm != tsig.GSS {
		rr.Error = dns.RcodeBadAlg

		return
	}

	s.m.Lock()
	defer s.m.Unlock()

	ctx, ok := s.ctx[keyname]

	switch tkey.Mode {
	case util.TkeyModeGSS:
		var (
			established bool
			expired     bool
		)

		if ok {
			if established, err = s.established(ctx); err != nil {
				rr.Error = dns.RcodeServerFailure

				return
			}

			if expired, err = s.expired(ctx); err != nil {
				rr.Error = dns.RcodeServerFailure

				return
			}
		}

		switch {
		case ok && established && !expired:
			rr.Error = dns.RcodeBadName

			return
		case ok && established && expired:
			delete(s.ctx, keyname)

			fallthrough
		case !ok:
			if ctx, err = s.newContext(); err != nil {
				s.logger.Error(err, "unable to create acceptor")

				rr.Error = dns.RcodeServerFailure

				return
			}
		}

		ctx, output, err := s.update(ctx, input)
		if err != nil {
			s.logger.Error(err, "unable to accept")

			rr.Error = dns.RcodeServerFailure

			return
		}

		s.ctx[keyname] = ctx

		rr.KeySize = uint16(len(output))
		rr.Key = hex.EncodeToString(output)

		if established, err = s.established(ctx); err != nil {
			rr.Error = dns.RcodeServerFailure

			return
		}

		if established {
			m.SetTsig(keyname, tsig.GSS, 300, time.Now().Unix())
		}

		s.logger.Info("outgoing", "response", m.String())
	case util.TkeyModeDelete: //nolint:wsl
		/*
			switch {
			case !ok:
				rr.Error = dns.RcodeBadName
			case r.IsTsig() != nil && w.TsigStatus() == nil:
				if err := s.delete(ctx); err != nil {
					rr.Error = dns.RcodeServerFailure

					return
				}

				delete(s.ctx, keyname)
			default:
				rr.Error = dns.RcodeNotAuth
			}
		*/

		fallthrough
	default:
		rr.Error = dns.RcodeBadMode
	}
}
