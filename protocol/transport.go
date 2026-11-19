// Package protocol implements primitives and interfaces of the base Apple MDM protocol.
package protocol

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/smallstep/pkcs7"
)

const (
	// MDMMIMEType identifies an Apple MDM command poll or result.
	MDMMIMEType = "application/x-apple-aspen-mdm"
	// CheckInMIMEType identifies an Apple MDM check-in request.
	CheckInMIMEType = "application/x-apple-aspen-mdm-checkin"

	// MDMSignatureHeader is the HTTP header name for the in-message
	// signature checking.
	MDMSignatureHeader = "Mdm-Signature"
)

var (
	ErrMissingDeviceIdentity = errors.New("missing device identity")
	ErrNilTransport          = errors.New("nil transport")
)

// Doer executes an HTTP request.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type IdentityProvider func(context.Context) (*x509.Certificate, crypto.PrivateKey, error)

// Transport encapsulates the MDM enrollment underlying MDM transport.
// The MDM channels utilize this transport to communicate with the host.
type Transport struct {
	checkInURL  string
	serverURL   string
	signMessage bool
	provider    IdentityProvider
	doer        Doer
}

type TransportOption func(*Transport)

// WithClient configures the HTTP client for this transport.
func WithClient(doer Doer) TransportOption {
	return func(t *Transport) {
		t.doer = doer
	}
}

// WithIdentityProvider configures the certificate and private key provider for this transport.
func WithIdentityProvider(f IdentityProvider) TransportOption {
	return func(t *Transport) {
		t.provider = f
	}
}

// WithMDMURLs ...
// checkInURL is optional per MDM spec.
func WithMDMURLs(serverURL, checkInURL string) TransportOption {
	return func(t *Transport) {
		t.serverURL = serverURL
		t.checkInURL = checkInURL
	}
}

// WithSignMessage ...
func WithSignMessage() TransportOption {
	return func(t *Transport) {
		t.signMessage = true
	}
}

func NewTransport(opts ...TransportOption) *Transport {
	t := &Transport{
		doer: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// SignMessage generates the CMS detached signature encoded as Base64.
func (t *Transport) SignMessage(ctx context.Context, body []byte) (string, error) {
	if t.provider == nil {
		return "", ErrMissingDeviceIdentity
	}
	cert, key, err := t.provider(ctx)
	if err != nil {
		return "", err
	}
	if cert == nil || key == nil {
		return "", ErrMissingDeviceIdentity
	}
	sd, err := pkcs7.NewSignedData(body)
	if err != nil {
		return "", err
	}
	err = sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{})
	if err != nil {
		return "", err
	}
	sd.Detach()
	sig, err := sd.Finish()
	return base64.StdEncoding.EncodeToString(sig), err
}

func (t *Transport) doRequest(ctx context.Context, body io.Reader, checkin bool) (*http.Response, error) {
	if t == nil {
		return nil, ErrNilTransport
	}
	var bodyBuf *bytes.Buffer
	if t.signMessage {
		bodyBuf = &bytes.Buffer{}
		if _, err := bodyBuf.ReadFrom(body); err != nil {
			return nil, fmt.Errorf("reading body into buffer: %w", err)
		}
		body = bodyBuf
	}

	url := t.serverURL
	if checkin && t.checkInURL != "" {
		url = t.checkInURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15")

	mime := MDMMIMEType
	if checkin {
		mime = CheckInMIMEType
	}
	req.Header.Set("Content-Type", mime)

	if t.signMessage {
		sig, err := t.SignMessage(ctx, bodyBuf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("generating mdm-signature: %w", err)
		}
		req.Header.Set(MDMSignatureHeader, sig)
	}

	return t.doer.Do(req)
}

// The caller is responsible for closing the response body.
func (t *Transport) DoCheckIn(ctx context.Context, body io.Reader) (*http.Response, error) {
	return t.doRequest(ctx, body, true)
}

// The caller is responsible for closing the response body.
func (t *Transport) DoReportResultsAndFetchNextCommand(ctx context.Context, body io.Reader) (*http.Response, error) {
	return t.doRequest(ctx, body, false)
}
