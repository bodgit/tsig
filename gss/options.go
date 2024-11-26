package gss

import "github.com/go-logr/logr"

// Option is the signature for all constructor options.
type Option[T Client | Server] func(*T) error

// WithLogger sets the logger used.
func WithLogger[T Client | Server](logger logr.Logger) Option[T] {
	return func(a *T) error {
		switch x := any(a).(type) {
		case *Client:
			x.logger = logger.WithName("client")
		case *Server:
			x.logger = logger.WithName("server")
		}

		return nil
	}
}

//nolint:nolintlint,unused
func unsupportedOption[T Client | Server](_ *T) error {
	return errNotSupported
}
