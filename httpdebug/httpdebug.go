// Package httpdebug provides utilities to assist the debugging
// of HTTP requests.
//
// Example usage:
//   import (
//     dbg "github.com/gmlewis/go-httpdebug/httpdebug"
//     "github.com/google/go-github/v43/github"
//     "golang.org/x/oauth2"
//   )
//
//   ...
//   ctx := context.Background()
//   ts := oauth2.StaticTokenSource(
//   	&oauth2.Token{AccessToken: token},
//   )
//   tc := &oauth2.Transport{Source: ts, Base: dbg.New()}
//
//   client := github.NewClient(&http.Client{Transport: tc})
//   ...
package httpdebug

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// CurlTransport is an http.RoundTripper that dumps HTTP requests
// as their `curl` equivalents.
type CurlTransport struct {
	// SecretHeaders contains a slice of secret header keys (case insensitive)
	// that should be redacted.
	// Default: ["authorization"].
	SecretHeaders []string

	// SecretParams contains a slice of secret query parameter strings
	// (case insensitive) in the URL that should be redacted.
	// Default: ["client_secret"].
	SecretParams []string

	// Transport specifies the mechanism by which individual
	// HTTP requests are made.
	// If nil, DefaultTransport is used.
	Transport http.RoundTripper
}

var _ http.RoundTripper = &CurlTransport{}

// CurlTransportOptions modify the behavior of the CurlTransport.
type CurlTransportOption func(*CurlTransport)

// New returns a new CurlTransport.
func New(opts ...CurlTransportOption) *CurlTransport {
	ct := &CurlTransport{
		SecretHeaders: []string{"authorization"},
		SecretParams:  []string{"client_secret"},
	}

	for _, opt := range opts {
		opt(ct)
	}

	return ct
}

// WithSecretHeader is a CurlTransportOption that adds an additional
// secret header key to be redacted from the reported URL.
// Empty secretHeader is ignored.
func WithSecretHeader(secretHeader string) func(*CurlTransport) {
	return func(ct *CurlTransport) {
		if secretHeader != "" {
			ct.SecretHeaders = append(ct.SecretHeaders, secretHeader)
		}
	}
}

// WithSecretParam is a CurlTransportOption that adds an additional
// secret query parameter to be redacted from the reported URL.
// Empty secretParam is ignored.
func WithSecretParam(secretParam string) func(*CurlTransport) {
	return func(ct *CurlTransport) {
		if secretParam != "" {
			ct.SecretParams = append(ct.SecretParams, secretParam)
		}
	}
}

// WithTransport is a CurlTransportOption that specifies the underlying
// http.RoundTripper used to perform individual HTTP requests.
func WithTransport(transport http.RoundTripper) func(*CurlTransport) {
	return func(ct *CurlTransport) {
		ct.Transport = transport
	}
}

// logger is user strictly for test purposes.
var logger = log.Println

// RoundTrip implements the http.RoundTripper interface.
func (t *CurlTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s, err := t.dumpRequestAsCurl(req)
	if err != nil {
		return nil, err
	}
	logger(s)

	// Make the HTTP request.
	return t.transport().RoundTrip(req)
}

// Client returns an *http.Client that makes requests.
func (t *CurlTransport) Client() *http.Client {
	return &http.Client{Transport: t}
}

func (t *CurlTransport) transport() http.RoundTripper {
	if t.Transport != nil {
		return t.Transport
	}
	return http.DefaultTransport
}

func escapeSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", `\'`)
}

// sanitizeURL redacts the SecretParams from the URL which may be
// exposed to the user.
func (t *CurlTransport) sanitizeURL(uri *url.URL) string {
	if uri == nil {
		return ""
	}
	newURL := *uri
	params := newURL.Query()
	for _, p := range t.SecretParams {
		if params.Get(p) != "" {
			params.Set(p, "REDACTED")
			newURL.RawQuery = params.Encode()
		}
	}
	return newURL.String()
}

// dumpRequestAsCurl dumps an outbound request as a curl command to a string
// for debugging purposes. It redacts any "Authorization" string in the
// header or client secret in the URL in order to prevent logging secrets.
func (t *CurlTransport) dumpRequestAsCurl(req *http.Request) (string, error) {
	lines := []string{
		fmt.Sprintf("curl -X %v", req.Method),
		t.sanitizeURL(req.URL),
	}

	var headers []string
	redactSecret := func(key string) bool {
		for _, secret := range t.SecretHeaders {
			if strings.EqualFold(key, secret) {
				headers = append(headers, fmt.Sprintf("-H '%v: <REDACTED>'", key))
				return true
			}
		}
		return false
	}

	for k, v := range req.Header {
		if redactSecret(k) {
			continue
		}
		headers = append(headers, fmt.Sprintf("-H '%v: %v'", k, escapeSingleQuote(strings.Join(v, ", "))))
	}

	sort.Strings(headers)
	lines = append(lines, headers...)

	if req.Body != nil {
		buf, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("-d '%v'", escapeSingleQuote(string(buf))))
		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))
	}

	return strings.Join(lines, " \\\n  "), nil
}
