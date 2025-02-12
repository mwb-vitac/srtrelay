package auth

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/voc/srtrelay/internal/metrics"
	"github.com/voc/srtrelay/stream"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var requestDurations = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace:                   metrics.Namespace,
		Subsystem:                   "auth",
		Name:                        "request_duration_seconds",
		Help:                        "A histogram of auth http request latencies.",
		Buckets:                     prometheus.DefBuckets,
		NativeHistogramBucketFactor: 1.1,
	},
	[]string{"url", "application"},
)

type httpAuth struct {
	config        HTTPAuthConfig
	client        *http.Client
	passphraseMap map[string]string
	mutex         sync.Mutex
}

type Duration time.Duration

type authInfo struct {
	Passphrase string
}

func (d *Duration) UnmarshalText(b []byte) error {
	x, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(x)
	return nil
}

type HTTPAuthConfig struct {
	URL           string
	Application   string
	Timeout       Duration // Timeout for Auth request
	PasswordParam string   // POST Parameter containing stream passphrase
}

// NewHttpAuth creates an Authenticator with a HTTP backend
func NewHTTPAuth(authConfig HTTPAuthConfig) Authenticator {
	m := requestDurations.MustCurryWith(prometheus.Labels{"url": authConfig.URL, "application": authConfig.Application})
	return &httpAuth{
		config: authConfig,
		client: &http.Client{
			Timeout:   time.Duration(authConfig.Timeout),
			Transport: promhttp.InstrumentRoundTripperDuration(m, http.DefaultTransport),
		},
		passphraseMap: map[string]string{},
	}
}

// Implement Authenticator

// Authenticate sends form-data in a POST-request to the configured url.
// If the response code is 2xx the publish/play is allowed, otherwise it is denied.
// This should be compatible with nginx-rtmps on_play/on_publish directives.
// https://github.com/arut/nginx-rtmp-module/wiki/Directives#on_play
func (h *httpAuth) Authenticate(streamid stream.StreamID) bool {
	response, err := h.client.PostForm(h.config.URL, url.Values{
		"call":                 {streamid.Mode().String()},
		"app":                  {h.config.Application},
		"name":                 {streamid.Name()},
		"username":             {streamid.Username()},
		h.config.PasswordParam: {streamid.Password()},
	})
	if err != nil {
		log.Println("http-auth:", err)
		return false
	}
	defer response.Body.Close()

	// store passphrase from response body for later use if needed
	bodyBytes, err := io.ReadAll(response.Body)
	if err == nil {
		var info authInfo
		err := json.Unmarshal(bodyBytes, &info)
		if err == nil {
			h.mutex.Lock()
			defer h.mutex.Unlock()
			h.passphraseMap[streamid.Password()] = info.Passphrase
		}
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false
	}

	return true
}

// Implement AuthSecure

// Return stored passphrase
func (h *httpAuth) GetPassphrase(streamid stream.StreamID) string {
	if streamid.Password() != "" {
		h.mutex.Lock()
		defer h.mutex.Unlock()
		passphrase, ok := h.passphraseMap[streamid.Password()]
		if ok {
			return passphrase
		}
	}
	return ""
}
