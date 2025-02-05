package auth

import (
	"testing"

	"github.com/voc/srtrelay/stream"
)

func Test_staticSecureAuth_Authenticate(t *testing.T) {
	tests := []struct {
		name       string
		allow      []string
		streamid   string
		passphrase string
		pass       bool
	}{
		{"NoPassphrase", []string{"play/*", "foobar"}, "play/foobar", "", true},
		{"MatchOne", []string{"", "play/*/abc"}, "play/foobar/abc", "0123456789", true},
		{"MatchAnother", []string{"play/foobar/*"}, "play/foobar/def", "9876543210", true},
		{"MatchNone", []string{"play/*"}, "play/foobar/ghi", "", true},
	}
	passphraseMap := map[string]string{"abc": "0123456789", "def": "9876543210"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewStaticSecureAuth(StaticAuthConfig{Allow: tt.allow},
				StaticSecureAuthConfig{PassphraseMap: passphraseMap})
			streamid := stream.StreamID{}
			if err := streamid.FromString(tt.streamid); err != nil {
				t.Error(err)
			}
			if got := auth.Authenticate(streamid); got != tt.pass {
				t.Errorf("%v StaticSecureAuth.Authenticate() = %v, pass %v", tt.name, got, tt.pass)
			}

			if passphrase := auth.GetPassphrase(streamid); passphrase != tt.passphrase {
				t.Errorf("%v StaticSecureAuth.GetPassphrase() = \"%v\", expected \"%v\"", tt.name, passphrase, tt.passphrase)
			}
		})
	}
}
