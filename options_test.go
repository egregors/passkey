package passkey

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithLogger(t *testing.T) {
	p := &Passkey{}
	setupDefaultOptions(p)

	defaultLogger := p.log
	customLogger := NewMockLogger(t)

	tests := []struct {
		name string
		l    Logger
		want Logger
	}{
		{
			name: "err: nil (default logger should be used)",
			l:    nil,
			want: defaultLogger,
		},
		{
			name: "succ: custom logger",
			l:    customLogger,
			want: customLogger,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithLogger(tt.l)
			opt(p)

			assert.Equal(t, tt.want, p.log)
		})
	}
}
