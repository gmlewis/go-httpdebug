package httpdebug

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/oauth2"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		opts []CurlTransportOption
		want *CurlTransport
	}{
		{
			name: "no opts",
			want: &CurlTransport{SecretHeaders: []string{"authorization"}, SecretParams: []string{"client_secret"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.opts...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithSecretHeader(t *testing.T) {
	tests := []struct {
		name         string
		secretHeader string
		want         *CurlTransport
	}{
		{
			name: "empty header",
			want: &CurlTransport{SecretHeaders: []string{"authorization"}, SecretParams: []string{"client_secret"}},
		},
		{
			name:         "new secret header",
			secretHeader: "Do-Not-Show",
			want:         &CurlTransport{SecretHeaders: []string{"authorization", "Do-Not-Show"}, SecretParams: []string{"client_secret"}},
		},
		{
			name:         "duplicate authorization - not harmful",
			secretHeader: "Authorization",
			want:         &CurlTransport{SecretHeaders: []string{"authorization", "Authorization"}, SecretParams: []string{"client_secret"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(WithSecretHeader(tt.secretHeader)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithSecretHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithSecretParam(t *testing.T) {
	tests := []struct {
		name        string
		secretParam string
		want        *CurlTransport
	}{
		{
			name: "empty param",
			want: &CurlTransport{SecretHeaders: []string{"authorization"}, SecretParams: []string{"client_secret"}},
		},
		{
			name:        "new secret param",
			secretParam: "id",
			want:        &CurlTransport{SecretHeaders: []string{"authorization"}, SecretParams: []string{"client_secret", "id"}},
		},
		{
			name:        "duplicate client_secret - not harmful",
			secretParam: "client_secret",
			want:        &CurlTransport{SecretHeaders: []string{"authorization"}, SecretParams: []string{"client_secret", "client_secret"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(WithSecretParam(tt.secretParam)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithSecretParam() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithTransport(t *testing.T) {
	ct := New()

	tests := []struct {
		name      string
		transport http.RoundTripper
		want      *CurlTransport
	}{
		{
			name: "nil transport",
			want: &CurlTransport{SecretHeaders: []string{"authorization"}, SecretParams: []string{"client_secret"}},
		},
		{
			name:      "non-nil transport",
			transport: ct,
			want:      &CurlTransport{SecretHeaders: []string{"authorization"}, SecretParams: []string{"client_secret"}, Transport: ct},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(WithTransport(tt.transport)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithTransport() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_escapeSingleQuote(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "empty string",
		},
		{
			name: "no single quotes",
			s:    "no single quotes",
			want: "no single quotes",
		},
		{
			name: "one single quote",
			s:    `I said, "I'd like that."`,
			want: `I said, "I\'d like that."`,
		},
		{
			name: "multiple single quotes",
			s:    `'I said, "I'd like that."'`,
			want: `\'I said, "I\'d like that."\'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeSingleQuote(tt.s); got != tt.want {
				t.Errorf("escapeSingleQuote() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCurlTransport_sanitizeURL(t *testing.T) {
	tests := []struct {
		name         string
		SecretParams []string
		url          string
		want         string
	}{
		{
			name: "nil uri",
		},
		{
			name: "no secret params",
			url:  "http://localhost:8080/api/endpoint",
			want: "http://localhost:8080/api/endpoint",
		},
		{
			name:         "default secret params but no usage",
			SecretParams: []string{"client_secret"},
			url:          "http://localhost:8080/api/endpoint",
			want:         "http://localhost:8080/api/endpoint",
		},
		{
			name:         "default secret params with usage",
			SecretParams: []string{"client_secret"},
			url:          "http://localhost:8080/api/endpoint?v=1&client_secret=DO-NOT-DIVULGE&x=abc",
			want:         "http://localhost:8080/api/endpoint?client_secret=REDACTED&v=1&x=abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &CurlTransport{
				SecretParams: tt.SecretParams,
			}
			var uri *url.URL
			if tt.url != "" {
				var err error
				uri, err = url.Parse(tt.url)
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := tr.sanitizeURL(uri); got != tt.want {
				t.Errorf("CurlTransport.sanitizeURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDumpRequestAsCurl(t *testing.T) {
	mkReq := func(method, inURL string, inBody string) *http.Request {
		var r io.Reader
		if inBody != "" {
			r = strings.NewReader(inBody)
		}
		req, _ := http.NewRequest(method, inURL, r)
		return req
	}

	tests := []struct {
		name   string
		req    *http.Request
		header http.Header
		want   string
	}{
		{
			name: "GET request, no auth",
			req:  mkReq("GET", "/foo", ""),
			want: `curl -X GET \
  /foo`,
		},
		{
			name: "GET request, with client secret",
			req:  mkReq("GET", "/foo?bar=5&client_secret=abc123", ""),
			want: `curl -X GET \
  /foo?bar=5&client_secret=REDACTED`,
		},
		{
			name: "POST request, no auth",
			req:  mkReq("POST", "/foo", `{"login":"l'a"}`),
			want: `curl -X POST \
  /foo \
  -d '{"login":"l\'a"}'`,
		},
		{
			name: "GET request, multiple accept, with auth",
			req:  mkReq("GET", "/foo", ""),
			header: http.Header{
				"Accept":        []string{"a'1", "a2", "a3"},
				"AuthoRizaTion": []string{"Bearer ABCD0123"},
			},
			want: `curl -X GET \
  /foo \
  -H 'Accept: a\'1, a2, a3' \
  -H 'AuthoRizaTion: <REDACTED>'`,
		},
	}

	ct := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.header {
				tt.req.Header[k] = v
			}

			got, err := ct.dumpRequestAsCurl(tt.req)
			if err != nil {
				t.Fatal(err)
			}

			if got != tt.want {
				t.Errorf("dumpRequestAsCurl =\n%v\nwant:\n%v", got, tt.want)
			}
		})
	}
}

func TestDumpRequestAsCurl_BadBody(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", strings.NewReader("yo"))
	req.Body = ioutil.NopCloser(iotest.ErrReader(errors.New("custom error")))

	ct := New()
	if _, err := ct.dumpRequestAsCurl(req); err == nil {
		t.Fatal("dumpRequestAsCurl expected error, got nil")
	}
}

// setup sets up a test HTTP server along with an http.Client that is
// configured to talk to that test server. Tests should register handlers on
// mux which provide mock responses for the API method being tested.
func setup() (client *http.Client, mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(mux)

	client = &http.Client{}

	return client, mux, server.URL, server.Close
}

func testMethod(t *testing.T, r *http.Request, want string) {
	t.Helper()
	if got := r.Method; got != want {
		t.Errorf("Request method: %v, want %v", got, want)
	}
}

func TestBareDo_GoodDebugRequestString(t *testing.T) {
	client, mux, url, teardown := setup()
	defer teardown()

	expectedBody := "Hello from the other side !"

	mux.HandleFunc("/test-url", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, expectedBody)
	})

	ct := New()
	client.Transport = ct

	req, err := http.NewRequest("GET", url+"/test-url", nil)
	if err != nil {
		t.Fatalf("http.NewRequest returned error: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do = %v, want nil", err)
	}

	got, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll returned error: %v", err)
	}
	if string(got) != expectedBody {
		t.Fatalf("Expected %q, got %q", expectedBody, string(got))
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("resp.Body.Close() returned error: %v", err)
	}
}

func TestBareDo_GoodDebugRequestStringButBodyError(t *testing.T) {
	client, mux, url, teardown := setup()
	defer teardown()

	expectedBody := "Hello from the other side !"

	mux.HandleFunc("/test-url", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, expectedBody)
	})

	ct := New()
	client.Transport = ct

	req, err := http.NewRequest("GET", url+"/test-url", nil)
	if err != nil {
		t.Fatalf("http.NewRequest returned error: %v", err)
	}
	want := "custom error"
	req.Body = ioutil.NopCloser(iotest.ErrReader(errors.New(want)))

	if _, err = client.Do(req); err == nil {
		t.Fatal("client.Do expected error but got nil")
	}

	got := err.Error()
	if !strings.Contains(got, want) {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func TestBareDo_GoodDebugRequestWithCustomTransport(t *testing.T) {
	client, mux, url, teardown := setup()
	defer teardown()

	expectedBody := "Hello from the other side !"

	mux.HandleFunc("/test-url", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprint(w, expectedBody)
	})

	ct := New()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: "SECRET"},
	)
	tc := &oauth2.Transport{Source: ts, Base: ct}
	client.Transport = tc

	req, err := http.NewRequest("GET", url+"/test-url", nil)
	if err != nil {
		t.Fatalf("http.NewRequest returned error: %v", err)
	}

	var curlCmd string
	logger = func(v ...interface{}) {
		if s, ok := v[0].(string); ok {
			curlCmd = s
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do = %v, want nil", err)
	}

	got, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll returned error: %v", err)
	}
	if string(got) != expectedBody {
		t.Fatalf("Expected %q, got %q", expectedBody, string(got))
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("resp.Body.Close() returned error: %v", err)
	}

	wantCurlCmd := fmt.Sprintf(`curl -X GET \
  %v/test-url \
  -H 'Authorization: <REDACTED>'`, url)

	if curlCmd != wantCurlCmd {
		t.Errorf("log.Println = (len=%v)\n%v\nwant: (len=%v)\n%v",
			len(curlCmd), curlCmd, len(wantCurlCmd), wantCurlCmd)
	}
}
