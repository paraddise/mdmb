package scepclient

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smallstep/scep"
	"github.com/smallstep/scep/x509util"
)

func TestFullSign(t *testing.T) {
	ca, caKey, err := SimpleSelfSignedRSAKeypair("Test SCEP CA", 1)
	if err != nil {
		t.Fatal(err)
	}
	const challenge = "test-challenge"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("operation") {
		case "GetCACaps":
			io.WriteString(w, "POSTPKIOperation\n")
		case "GetCACert":
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Write(ca.Raw)
		case "PKIOperation":
			if r.Method != http.MethodPost || r.URL.Query().Has("message") ||
				r.Header.Get("Content-Type") != "application/x-pki-message" {
				t.Error("expected SCEP POST with the request in its body")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			message, err := scep.ParsePKIMessage(body)
			if err == nil {
				err = message.DecryptPKIEnvelope(ca, caKey)
			}
			if err != nil {
				t.Error(err)
				return
			}
			if message.CSRReqMessage.ChallengePassword != challenge {
				t.Error("request did not include the SCEP challenge")
			}
			csr := message.CSRReqMessage.CSR
			issued := *ca
			issued.Subject = csr.Subject
			der, err := x509.CreateCertificate(rand.Reader, &issued, ca, csr.PublicKey, caKey)
			if err != nil {
				t.Error(err)
				return
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Error(err)
				return
			}
			reply, err := message.Success(ca, caKey, cert)
			if err != nil {
				t.Error(err)
				return
			}
			w.Write(reply.Raw)
		default:
			http.Error(w, "unsupported operation", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := SimpleSelfSignedRSAKeypair("Test SCEP identity", 1)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{SignatureAlgorithm: x509.SHA256WithRSA},
		ChallengePassword:  challenge,
	}
	raw, err := x509util.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := client.FullSign(context.Background(), csr, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil || !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("issued certificate does not match the requested key")
	}
}
