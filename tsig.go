package tsig

const (
	_ uint16 = iota // Reserved, RFC 2930, section 2.5
	// TkeyModeServer is used for server assigned keying
	TkeyModeServer
	// TkeyModeDH is used for Diffie-Hellman exchanged keying
	TkeyModeDH
	// TkeyModeGSS is used for GSS-API establishment
	TkeyModeGSS
	// TkeyModeResolver is used for resolver assigned keying
	TkeyModeResolver
	// TkeyModeDelete is used for key deletion
	TkeyModeDelete
)
