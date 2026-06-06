package tsig

import (
	"errors"

	dnsv1 "github.com/miekg/dns"
)

type multiProvider struct {
	providers []dnsv1.TsigProvider
}

func (mp *multiProvider) Generate(msg []byte, t *dnsv1.TSIG) (b []byte, err error) {
	for _, p := range mp.providers {
		if b, err = p.Generate(msg, t); err == nil || !errors.Is(err, dnsv1.ErrKeyAlg) {
			return
		}
	}

	return nil, dnsv1.ErrKeyAlg
}

func (mp *multiProvider) Verify(msg []byte, t *dnsv1.TSIG) (err error) {
	for _, p := range mp.providers {
		if err = p.Verify(msg, t); err == nil || !errors.Is(err, dnsv1.ErrKeyAlg) {
			return
		}
	}

	return dnsv1.ErrKeyAlg
}

// MultiProvider creates a [dnsv1.TsigProvider] that chains the provided input
// providers. This allows multiple TSIG algorithms.
//
// Each provider is called in turn and if it returns [dnsv1.ErrKeyAlg] the next
// provider in the list is tried. On success or any other error, the result is
// returned; it does not continue down the list.
func MultiProvider(providers ...dnsv1.TsigProvider) dnsv1.TsigProvider {
	allProviders := make([]dnsv1.TsigProvider, 0, len(providers))

	for _, p := range providers {
		if mp, ok := p.(*multiProvider); ok {
			allProviders = append(allProviders, mp.providers...)
		} else {
			allProviders = append(allProviders, p)
		}
	}

	return &multiProvider{allProviders}
}
