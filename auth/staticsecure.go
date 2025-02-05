package auth

import (
	"github.com/voc/srtrelay/stream"
)

// StaticSecureAuth implements both the Authenticator and AuthSecure interfaces
// by extending StaticAuth with the GetPassphrase method.

type staticSecureAuth struct {
	base          Authenticator
	passphraseMap map[string]string
}

type StaticSecureAuthConfig struct {
	PassphraseMap map[string]string
}

// NewStaticSecureAuth creates an Authenticator with a static config backend
// including passphrase support
func NewStaticSecureAuth(config StaticAuthConfig, config2 StaticSecureAuthConfig) *staticSecureAuth {
	return &staticSecureAuth{
		base:          NewStaticAuth(config),
		passphraseMap: config2.PassphraseMap,
	}
}

// Implement Authenticator

// Authenticate delegates to the base StaticAuth implementation.
func (authReceiver *staticSecureAuth) Authenticate(streamid stream.StreamID) bool {
	return authReceiver.base.Authenticate(streamid)
}

// Implement AuthSecure

// Return the passphrase from the locally configured passphraseMap,
// using the <password> portion of StreamID as key.
func (auth *staticSecureAuth) GetPassphrase(streamid stream.StreamID) string {
	if streamid.Password() != "" {
		passphrase, ok := auth.passphraseMap[streamid.Password()]
		if ok {
			return passphrase
		}
	}
	return ""
}
