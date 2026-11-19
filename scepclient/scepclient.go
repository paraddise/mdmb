package scepclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

// Doer executes an HTTP request.
type Doer interface {
	// Execute HTTP request.
	Do(*http.Request) (*http.Response, error)
}

type IdentityProvider func(ctx context.Context) (*x509.Certificate, *rsa.PrivateKey, error)

type Client struct {
	scepURL string
	doer    Doer

	caps  []byte
	certs []*x509.Certificate

	signerProvider IdentityProvider
}

type Option func(*Client)

func WithClient(doer Doer) Option {
	return func(c *Client) {
		c.doer = doer
	}
}

func WithSignerKeypair(p IdentityProvider) Option {
	return func(c *Client) {
		c.signerProvider = p
	}
}

func New(scepURL string, opts ...Option) (*Client, error) {
	c := &Client{
		scepURL: scepURL,
		doer:    http.DefaultClient,
		signerProvider: func(context.Context) (*x509.Certificate, *rsa.PrivateKey, error) {
			// generate a new keypair
			return SimpleSelfSignedRSAKeypair("SCEP CLIENT", 1)
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

func (c *Client) supportsCap(cap string) bool {
	return bytes.Contains(c.caps, []byte(cap))
}

// httpMethod selects an HTTP method depending on operation and server capabilities.
func (c *Client) httpMethod(op string) string {
	if op == "PKIOperation" && (c.supportsCap("POSTPKIOperation") || c.supportsCap("SCEPStandard")) {
		return http.MethodPost
	}
	return http.MethodGet
}

// Caller is responsible for closing the response body.
func (c *Client) do(ctx context.Context, op string, message []byte) (*http.Response, error) {
	method := c.httpMethod(op)

	var body io.Reader
	if len(message) > 0 && method == http.MethodPost {
		// include the message as the (raw) HTTP body only when
		// a message is present and for POST (PKIOperation) requests
		body = bytes.NewBuffer(message)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.scepURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CertificateService/1 CFNetwork/3826.400.120 Darwin/24.3.0")

	q := req.URL.Query()
	q.Set("operation", op)
	if method != http.MethodPost && len(message) > 0 {
		// GET carries the encoded SCEP message in the query. POST carries it in the body.
		value := string(message)
		if op == "PKIOperation" {
			value = base64.URLEncoding.EncodeToString(message)
		}
		q.Set("message", value)
	}
	req.URL.RawQuery = q.Encode()

	if method == http.MethodPost {
		// some servers/proxies have problems without a content-type
		req.Header.Set("Content-Type", "application/x-pki-message")
	}

	return c.doer.Do(req)
}

const Limit1MB = 1024 * 1024

func (c *Client) GetCACaps(ctx context.Context) ([]byte, error) {
	resp, err := c.do(ctx, "GetCACaps", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SCEP server returned HTTP %d", resp.StatusCode)
	}

	c.caps, err = io.ReadAll(io.LimitReader(resp.Body, Limit1MB))
	return c.caps, err
}

// Including message as part of GetCACert is not a part of RFC8894.
func (c *Client) GetCACert(ctx context.Context, message []byte) ([]*x509.Certificate, error) {
	resp, err := c.do(ctx, "GetCACert", message)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SCEP server returned HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, Limit1MB))
	if err != nil {
		return nil, err
	}

	switch resp.Header.Get("Content-Type") {
	case "application/x-x509-ca-cert":
		cert, err := x509.ParseCertificate(bodyBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		c.certs = append(c.certs, cert)
	case "application/x-x509-ca-ra-cert":
		p7, err := pkcs7.Parse(bodyBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing degenerate CMS: %w", err)
		}
		c.certs = p7.Certificates
	default:
		return nil, fmt.Errorf("unknown content-type: %s", resp.Header.Get("Content-Type"))
	}

	return c.certs, nil
}

func (c *Client) Sign(ctx context.Context, csr *x509.CertificateRequest, selector scep.CertsSelector) (*x509.Certificate, error) {
	if selector == nil {
		selector = scep.NopCertsSelector()
	}

	tmpl := &scep.PKIMessage{
		MessageType: scep.PKCSReq,
		Recipients:  selector.SelectCerts(c.certs),
		// CSRReqMessage: &scep.CSRReqMessage{
		// 	ChallengePassword: "",
		// },
	}

	if len(tmpl.Recipients) == 0 {
		return nil, errors.New("no CA certificates match the SCEP certificate selector")
	}

	var err error
	tmpl.SignerCert, tmpl.SignerKey, err = c.signerProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieving signer identity: %w", err)
	}

	pkiMessageReq, err := scep.NewCSRRequest(csr, tmpl)
	if err != nil {
		return nil, fmt.Errorf("creating csr request: %w", err)
	}

	resp, err := c.do(ctx, "PKIOperation", pkiMessageReq.Raw)
	if err != nil {
		return nil, fmt.Errorf("executing PKIOperation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SCEP server returned HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, Limit1MB))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	respMsg, err := scep.ParsePKIMessage(respBody, scep.WithCACerts(c.certs))
	if err != nil {
		return nil, fmt.Errorf("parsing response pki message: %w", err)
	}

	if respMsg.MessageType != scep.CertRep || respMsg.CertRepMessage == nil ||
		respMsg.TransactionID != pkiMessageReq.TransactionID ||
		!bytes.Equal(respMsg.RecipientNonce, pkiMessageReq.SenderNonce) {
		return nil, errors.New("SCEP response does not match the enrollment request")
	}

	switch respMsg.PKIStatus {
	case scep.FAILURE:
		return nil, fmt.Errorf("scep failure: fail info: %s", respMsg.FailInfo)
	case scep.PENDING:
		return nil, errors.New("pending response not supported")
	case scep.SUCCESS:
	default:
		return nil, fmt.Errorf("unknown scep pki status: %s", respMsg.PKIStatus)
	}

	err = decryptReply(respMsg, tmpl.SignerCert, tmpl.SignerKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting response pki message: %w", err)
	}

	return respMsg.CertRepMessage.Certificate, nil
}

func (c *Client) FullSign(ctx context.Context, csr *x509.CertificateRequest, caMessage []byte, selector scep.CertsSelector) (*x509.Certificate, error) {
	_, err := c.GetCACaps(ctx)
	if err != nil {
		return nil, fmt.Errorf("error GetCACaps: %w", err)
	}

	_, err = c.GetCACert(ctx, caMessage)
	if err != nil {
		return nil, fmt.Errorf("error GetCACert: %w", err)
	}

	cert, err := c.Sign(ctx, csr, selector)
	if err != nil {
		return nil, fmt.Errorf("error PKIOperation: %w", err)
	}

	return cert, nil
}

func decryptReply(message *scep.PKIMessage, cert *x509.Certificate, key crypto.PrivateKey) (err error) {
	// The CMS dependency can panic on malformed ciphertext or an empty certificate list.
	defer func() {
		if recover() != nil {
			err = errors.New("malformed SCEP certificate envelope")
		}
	}()
	return message.DecryptPKIEnvelope(cert, key)
}
