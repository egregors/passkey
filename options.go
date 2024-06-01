package passkey

type Option func(*Passkey)

func WithLogger(l Logger) Option {
	return func(p *Passkey) {
		p.l = l
	}
}
