package passkey

type Option func(*Passkey)

// WithLogger sets the logger for the passkey instance.
func WithLogger(l Logger) Option {
	return func(p *Passkey) {
		if l != nil {
			p.l = l
		}
	}
}
