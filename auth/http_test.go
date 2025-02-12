package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/voc/srtrelay/stream"
)

func serverMock() *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Ok"))
	})
	handler.HandleFunc("/unauthorized", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
	})
	handler.HandleFunc("/passphrase", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{ \"passphrase\": \"0123456789\" }"))
	})

	srv := httptest.NewServer(handler)

	return srv
}

func Test_httpAuth_Authenticate(t *testing.T) {
	srv := serverMock()
	defer srv.Close()

	tests := []struct {
		name       string
		url        string
		want       bool
		passphrase string
	}{
		{"AuthOk", "/ok", true, ""},
		{"AuthFail", "/unauthorized", false, ""},
		{"AuthPassphrase", "/passphrase", true, "0123456789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewHTTPAuth(HTTPAuthConfig{
				URL: srv.URL + tt.url,
			})

			streamid := stream.StreamID{}
			streamid.FromString("publish/teststream/abc")

			if got := auth.Authenticate(streamid); got != tt.want {
				t.Errorf("httpAuth.Authenticate() = %v, want %v", got, tt.want)
			}

			// convert auth to an AuthSecure
			authSecure, ok := auth.(AuthSecure)
			var passphrase string
			if ok {
				passphrase = authSecure.GetPassphrase(streamid)
			}
			if passphrase != tt.passphrase {
				t.Errorf("httpAuth.GetPassphrase() = %v, want %v", passphrase, tt.passphrase)
			}
		})
	}
}
