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
	messages string
	logging  bool
}

type DigestTransport struct {
	Client   *http.Client
	Password string
	Username string
	logging  bool
}

// NewDigestRequest creates a new DigestRequest object
func NewDigestRequest(username, password, method, uri, body string, client *http.Client, header http.Header) DigestRequest {
	dr := DigestRequest{}
	dr.log("DigestRequest created in NewDigestRequest()")
	dr.UpdateRequestWithContext(context.Background(), username, password, method, uri, body, client, header)
	return dr
}

// NewDigestRequestWithContext creates a new DigestRequest
//  object passing along the provided context
func NewDigestRequestWithContext(ctx context.Context, username, password, method, uri, body string, client *http.Client, header http.Header) DigestRequest {
	dr := DigestRequest{}
	dr.log("DigestRequest created in NewDigestRequestWithContext()")
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

func (dt *DigestTransport) SetLogging(enabled bool) {
	dt.logging = enabled
}

func (dr *DigestRequest) SetLogging(enabled bool) {
	dr.log("Logging set to %t", enabled) // Either of these logs will be effective if switching...
	dr.logging = enabled
	dr.log("Logging set to %t", enabled) // Either of these logs will be effective if switching...
}

func (dr *DigestRequest) log(format string, args ...any) {
	if dr.logging {
		dr.messages += fmt.Sprintf(format+"\n", args)
	}
}

// UpdateRequest is called when you want to reuse an existing
//  DigestRequest connection with new request information.
// Note that original context is reused, meaning that a specified
//  context timeout is not reset when using this function.
func (dr *DigestRequest) UpdateRequest(username, password, method, uri, body string, client *http.Client, header http.Header) *DigestRequest {
	dr.log("UpdateRequest()")
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
	dr.log("UpdateRequestWithContext()")
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
func (dt *DigestTransport) RoundTrip(req *http.Request) (resp *http.Response, err error, messages string) {
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
	dr.SetLogging(dt.logging)
	return dr.Execute()
}

// Execute initialise the request and get a response
func (dr *DigestRequest) Execute() (resp *http.Response, err error, messages string) {
	dr.log("Execute()")

	if dr.Auth != nil {
		dr.log("Execute() - dr.Auth != nil")
		return dr.executeExistingDigest()
	}

	var req *http.Request
	if req, err = http.NewRequestWithContext(dr.Context, dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		dr.log("Error in Execute() in call to http.NewRequestWithContext()")
		return nil, err, dr.messages
	}
	dr.addHeaders(req)

	if dr.Client == nil {
		dr.log("Execute() - dr.Client == nil")
		dr.Client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	if resp, err = dr.Client.Do(req); err != nil {
		dr.log("Error in Execute() in call to dr.Client.Do(): %v", err)
		return nil, err, dr.messages
	}

	if resp.StatusCode == 401 {
		dr.log("Execute() - response was status 401, calling executeNewDigest()\n")
		return dr.executeNewDigest(resp)
	}

	// return the resp to user to handle resp.body.Close()
	dr.log("Execute() - no 401, sending back the response")
	return resp, nil, dr.messages
}

func (dr *DigestRequest) executeNewDigest(resp *http.Response) (resp2 *http.Response, err error, messages string) {
	var (
		auth     *authorization
		wa       *wwwAuthenticate
		waString string
	)

	dr.log("executeNewDigest()")

	// body not required for authentication, closing
	resp.Body.Close()

	if waString = resp.Header.Get("WWW-Authenticate"); waString == "" {
		dr.log("executeNewDigest() - Failed to get WWW-Authenticate header: %v", err)
		return nil, fmt.Errorf("failed to get WWW-Authenticate header, please check your server configuration"), dr.messages
	}
	wa = newWwwAuthenticate(waString)
	dr.Wa = wa

	if auth, err = newAuthorization(dr); err != nil {
		dr.log("executeNewDigest() - newAuthorization() failed: %v", err)
		return nil, err, dr.messages
	}

	if resp2, err, _ = dr.executeDigestRequest(auth.toString()); err != nil {
		dr.log("executeNewDigest() - executeDigestRequest() failed: %v", err)
		return nil, err, dr.messages
	}

	dr.Auth = auth
	return resp2, nil, dr.messages
}

func (dr *DigestRequest) executeExistingDigest() (resp *http.Response, err error, messages string) {
	var auth *authorization

	dr.log("executeExistingDigest()\n")

	if auth, err = dr.Auth.refreshAuthorization(dr); err != nil {
		dr.log("executeExistingDigest() - refreshAuthorization() failed: %v", err)
		return nil, err, dr.messages
	}
	dr.Auth = auth

	return dr.executeDigestRequest(dr.Auth.toString())
}

func (dr *DigestRequest) executeDigestRequest(authString string) (resp *http.Response, err error, messages string) {
	var req *http.Request

	dr.log("executeDigestRequest()")

	if req, err = http.NewRequestWithContext(dr.Context, dr.Method, dr.Uri, bytes.NewReader([]byte(dr.Body))); err != nil {
		dr.log("executeDigestRequest() - NewRequestWithContext failed: %v", err)
		return nil, err, dr.messages
	}
	dr.addHeaders(req)
	req.Header.Add("Authorization", authString)

	if dr.Client == nil {
		dr.log("executeDigestRequest() - dr.Client == nil")
		dr.Client = &http.Client{}
	}

	dr.log("executeDigestRequest() - Calling Client.Do()")
	resp, err = dr.Client.Do(req)
	return resp, err, dr.messages
}

func (dr *DigestRequest) addHeaders(req *http.Request) {
	dr.log("addHeaders()")
	req.Header = dr.Header.Clone()
}
