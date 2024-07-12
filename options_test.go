package passkey

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithLogger(t *testing.T) {
	customLogger := NewMockLogger(t)

	tests := []struct {
		name string
		l    Logger
		want Logger
	}{
		{
			name: "err: nil (default logger should be used)",
			l:    nil,
			want: NullLogger{},
		},
		{
			name: "succ: custom logger",
			l:    customLogger,
			want: customLogger,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Passkey{
				l: NullLogger{}, // default logger
			}
			opt := WithLogger(tt.l)
			opt(p)

			assert.Equal(t, tt.want, p.l)
		})
	}
}
