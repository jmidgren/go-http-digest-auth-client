package digest_auth_client

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"
)

type DigestRequest struct {
	Context  context.Context
	Client   *http.Client
	Body     string
	Method   string
	Password string
	Uri      string
	Username string
	Header   http.Header
	Auth     *authorization
	Wa       *wwwAuthenticate
}

type DigestTransport struct {
	Client   *http.Client
	Password string
	Username string
}

// NewDigestRequest creates a new DigestRequest object
func NewDigestRequest(username, password, method, uri, body string, client *http.Client, header http.Header) DigestRequest {
	dr := DigestRequest{}
	dr.UpdateRequestWithContext(context.Background(), username, password, method, uri, body, client, header)
	return dr
}

// NewDigestRequestWithContext creates a new DigestRequest
//  object passing along the provided context
func NewDigestRequestWithContext(ctx context.Context, username, password, method, uri, body string, client *http.Client, header http.Header) DigestRequest {
	dr := DigestRequest{}
	dr.UpdateRequestWithContext(ctx, username, password, method, uri, body, client, header)
	return dr
}

// NewDigestTransport creates a new DigestTransport object
func NewDigestTransport(username, password string, client *http.Client) DigestTransport {
	dt := DigestTransport{}
	dt.Client = client
	dt.Password = password
	dt.Username = username
	return dt
}

// UpdateRequest is called when you want to reuse an existing
//  DigestRequest connection with new request information.
// Note that original context is reused, meaning that a specified
//  context timeout is not reset when using this function.
func (dr *DigestRequest) UpdateRequest(username, password, method, uri, body string, client *http.Client, header http.Header) *DigestRequest {
	dr.Body = body
	dr.Method = method
	dr.Password = password
	dr.Uri = uri
	dr.Username = username
	dr.Client = client
	dr.Header = header
	return dr
}

// UpdateRequestWithContext is called when you want to reuse an
//  existing DigestRequest connection with new request information
//  also specifying the context
func (dr *DigestRequest) UpdateRequestWithContext(ctx context.Context, username, password, method, uri, body string, client *http.Client, header http.Header) *DigestRequest {
	dr.Context = ctx
	dr.Body = body
	dr.Method = method
	dr.Password = password
	dr.Uri = uri
	dr.Username = username
	dr.Client = client
	dr.Header = header
	return dr
}

// RoundTrip implements the http.RoundTripper interface
func (dt *DigestTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	ctx := req.Context()
	username := dt.Username
	password := dt.Password
	method := req.Method
	uri := req.URL.String()
	header := req.Header

	var body string
	if req.Body != nil {
		buf := new(bytes.Buffer)
		buf.ReadFrom(req.Body)
		body = buf.String()
	}

	dr := NewDigestRequestWithContext(ctx, username, password, method, uri, body, dt.Client, header)
	return dr.Execute()
}

// Execute initialise the request and get a response
func (dr *DigestRequest) Execute() (resp *http.Response, err error) {

	if dr.Auth != nil {
		return dr.executeExistingDigest()
	}

	var req *http.Request
	if req, err = http.NewRequestWithContext(dr.Context, dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		return nil, err
	}
	dr.addHeaders(req)

	if dr.Client == nil {
		dr.Client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	if resp, err = dr.Client.Do(req); err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		return dr.executeNewDigest(resp)
	}

	// return the resp to user to handle resp.body.Close()
	return resp, nil
}

func (dr *DigestRequest) executeNewDigest(resp *http.Response) (resp2 *http.Response, err error) {
	var (
		auth     *authorization
		wa       *wwwAuthenticate
		waString string
	)

	// body not required for authentication, closing
	resp.Body.Close()

	if waString = resp.Header.Get("WWW-Authenticate"); waString == "" {
		return nil, fmt.Errorf("failed to get WWW-Authenticate header, please check your server configuration")
	}
	wa = newWwwAuthenticate(waString)
	dr.Wa = wa

	if auth, err = newAuthorization(dr); err != nil {
		return nil, err
	}

	if resp2, err = dr.executeDigestRequest(auth.toString()); err != nil {
		return nil, err
	}

	dr.Auth = auth
	return resp2, nil
}

func (dr *DigestRequest) executeExistingDigest() (resp *http.Response, err error) {
	var auth *authorization

	if auth, err = dr.Auth.refreshAuthorization(dr); err != nil {
		return nil, err
	}
	dr.Auth = auth

	return dr.executeDigestRequest(dr.Auth.toString())
}

func (dr *DigestRequest) executeDigestRequest(authString string) (resp *http.Response, err error) {
	var req *http.Request

	if req, err = http.NewRequestWithContext(dr.Context, dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		return nil, err
	}
	dr.addHeaders(req)
	req.Header.Add("Authorization", authString)

	if dr.Client == nil {
		dr.Client = &http.Client{}
	}

	return dr.Client.Do(req)
}

func (dr *DigestRequest) addHeaders(req *http.Request) {
	req.Header = dr.Header.Clone()
}
