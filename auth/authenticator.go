package auth

import "github.com/voc/srtrelay/stream"

type Authenticator interface {
	Authenticate(stream.StreamID) bool
}

type AuthSecure interface {
	GetPassphrase(stream.StreamID) string
}
