package tui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/jessepeterson/mdmb/internal/device"
	"github.com/jessepeterson/mdmb/protocol"
	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
	plist "howett.net/plist"
)

func TestSCEPEnrollmentAndCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db := openTestDB(t, path)
	first := createDevice(t, db, "First device")
	second := createDevice(t, db, "Second device")
	ca, requests, failing, blocked := runTestSCEPServer(t)

	var pending atomic.Pointer[[]byte]
	var acknowledgments atomic.Int32
	var signingCert atomic.Pointer[x509.Certificate]
	mdm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		sig, err := base64.StdEncoding.DecodeString(r.Header.Get(protocol.MDMSignatureHeader))
		if err != nil {
			t.Error(err)
			return
		}
		p7, err := pkcs7.Parse(sig)
		if err != nil {
			t.Error(err)
			return
		}
		p7.Content = body
		if signer := p7.GetOnlySigner(); signer == nil || !signer.Equal(signingCert.Load()) || p7.Verify() != nil {
			t.Error("poll must be signed by the initial MDM identity")
		}
		var response device.ConnectRequest
		if _, err := plist.Unmarshal(body, &response); err != nil {
			t.Error(err)
			return
		}
		if response.CommandUUID == "install" {
			if response.Status != "Acknowledged" {
				t.Errorf("InstallProfile returned %s", response.Status)
			}
			acknowledgments.Add(1)
			return
		}
		if raw := pending.Load(); raw != nil {
			w.Write(marshalTestPlist(t, map[string]any{
				"CommandUUID": "install",
				"Command":     map[string]any{"RequestType": "InstallProfile", "Payload": *raw},
			}))
		}
	}))
	defer mdm.Close()
	mdmCert := seedEnrollment(t, db, first, mdm.URL)
	signingCert.Store(mdmCert)
	otherCert := seedEnrollment(t, db, second, mdm.URL)

	manual := encryptedSCEPProfile(t, mdmCert, "manual", ca.URL, "Manual %ComputerName%")
	old := encryptedSCEPProfile(t, mdmCert, "old", ca.URL, "Previously stored")
	newProfile := encryptedSCEPProfile(t, mdmCert, "new", ca.URL, "New delivery")
	for _, raw := range [][]byte{manual, old} {
		if err := first.InstallProfile(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
	}
	m := newModel(db, context.Background())
	m.openDevice(first.UDID)
	press := func(key rune) tea.Cmd {
		return m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
	}
	poll := func() {
		t.Helper()
		result := m.startPoll()().(pollResult)
		m.finishPoll(result)
		if result.err != nil {
			t.Fatal(result.err)
		}
	}
	poll()
	if requests.Load() != 0 || m.autoSCEP {
		t.Fatal("auto enrollment must default to off for an existing device")
	}

	m.reloadProfiles("manual")
	m.openProfile()
	press('s')
	press('e')
	if m.screen != confirmEnrollScreen || !strings.Contains(m.View(), "127.0.0.1:") || !strings.Contains(m.View(), "manual certificate") {
		t.Fatalf("SCEP confirmation missing payload or host: %s", m.View())
	}
	cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	m.finishEnroll(cmd().(enrollResult))
	if len(m.scepPayloads) != 1 || m.scepPayloads[0].Status.State != "Issued" || requests.Load() != 1 {
		t.Fatalf("manual issuance: %+v, %s", m.scepPayloads, m.status)
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != certificateScreen || !strings.Contains(m.viewText, "SHA-256 fingerprint:") || !strings.Contains(m.viewText, "Manual First device") {
		t.Fatalf("issued certificate details: %s", m.viewText)
	}
	for _, pemMode := range []bool{false, true} {
		if pemMode {
			press('t')
		}
		press('e')
		expectedName := "certificate.txt"
		if pemMode {
			expectedName = "certificate.pem"
		}
		if m.exportPath.Value() != expectedName {
			t.Fatal(m.exportPath.Value())
		}
		dest := filepath.Join(t.TempDir(), expectedName)
		m.exportPath.SetValue(dest)
		m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
		raw, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		if pemMode {
			block, _ := pem.Decode(raw)
			if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, m.certificates[m.certificateIndex].X509.Raw) {
				t.Fatal("PEM export did not contain the issued certificate")
			}
		} else if string(raw) != m.certificates[m.certificateIndex].Text() {
			t.Fatal("text export differed from certificate details")
		}
		press('e')
		m.exportPath.SetValue(dest)
		m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
		if m.screen != exportScreen || !strings.Contains(m.status, "file exists") {
			t.Fatalf("existing destination accepted: %s", m.status)
		}
		m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	}

	m.openDevice(first.UDID)
	press('a')
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openTestDB(t, path)
	m = newModel(db, context.Background())
	m.openDevice(second.UDID)
	press('k')
	if m.autoSCEP || len(m.certificates) != 1 || !m.certificates[0].X509.Equal(otherCert) || !m.certificates[0].MDMIdentity {
		t.Fatal("certificate or setting leaked into another device")
	}
	m.openDevice(first.UDID)
	if !m.autoSCEP {
		t.Fatal("auto setting did not survive reopening Bolt")
	}
	pending.Store(&newProfile)
	poll()
	redelivered := encryptedSCEPProfile(t, mdmCert, "new", ca.URL, "New delivery")
	pending.Store(&redelivered)
	poll()
	if requests.Load() != 3 || acknowledgments.Load() != 2 {
		t.Fatalf("automatic enrollment and repeated delivery: %d SCEP requests, %d acknowledgments", requests.Load(), acknowledgments.Load())
	}

	failing.Store(true)
	changed := encryptedSCEPProfile(t, mdmCert, "new", ca.URL, "Changed payload")
	pending.Store(&changed)
	poll()
	if requests.Load() != 4 || acknowledgments.Load() != 3 || !strings.Contains(m.diagnostics, "HTTP 503") {
		t.Fatalf("failure must be diagnosed after acknowledging the profile: %d %d %s", requests.Load(), acknowledgments.Load(), m.diagnostics)
	}
	raw, err := m.selected.SystemProfileStore().Raw("new")
	if err != nil || !bytes.Equal(raw, changed) {
		t.Fatal("MDM install did not preserve original profile bytes")
	}
	rows, err := m.selected.SCEPPayloads("new")
	if err != nil || len(rows) != 1 || rows[0].Status.State != "Failed" {
		t.Fatalf("saved failure: %+v %v", rows, err)
	}
	poll()
	if requests.Load() != 4 {
		t.Fatal("automatic retry of the failed version")
	}
	failing.Store(false)

	// Hold the SCEP response while two manual attempts overlap.
	gate := make(chan struct{})
	blocked.Store(&gate)
	defer func() {
		if blocked.Load() != nil {
			close(gate)
		}
	}()
	var wg sync.WaitGroup
	results := make(chan device.SCEPStatus, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := m.selected.EnrollSCEP(context.Background(), "new", rows[0].Version)
			if err != nil {
				t.Error(err)
			}
			results <- result
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for requests.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	blocked.Store(nil)
	close(gate)
	wg.Wait()
	a, b := <-results, <-results
	if requests.Load() != 5 || a != b || a.State != "Issued" {
		t.Fatalf("retry and deduplication: %d requests, %+v, %+v", requests.Load(), a, b)
	}

	// A cancellation after the request starts is persisted and skipped on later polls.
	cancelProfile := encryptedSCEPProfile(t, mdmCert, "cancel", ca.URL, "Cancelled")
	if err := m.selected.InstallProfile(context.Background(), cancelProfile); err != nil {
		t.Fatal(err)
	}
	m.reloadProfiles("cancel")
	m.openProfile()
	press('s')
	press('e')
	cancelGate := make(chan struct{})
	defer close(cancelGate)
	blocked.Store(&cancelGate)
	command := m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	finished := make(chan enrollResult, 1)
	go func() { finished <- command().(enrollResult) }()
	deadline = time.Now().Add(5 * time.Second)
	for requests.Load() < 6 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	result := <-finished
	blocked.Store(nil)
	m.finishEnroll(result)
	if requests.Load() != 6 || !errors.Is(result.err, context.Canceled) || m.scepPayloads[0].Status.State != "Cancelled" {
		t.Fatalf("cancelled enrollment: %d requests, %v, %+v", requests.Load(), result.err, m.scepPayloads)
	}
	pending.Store(nil)
	poll()
	if requests.Load() != 6 {
		t.Fatal("automatic retry of the cancelled version")
	}

	m.openDevice(first.UDID)
	press('k')
	if len(m.certificates) != 5 || !strings.Contains(m.certificatesView(), "MDM identity") {
		t.Fatalf("expected original identity and four issued certificates: %s", m.certificatesView())
	}
	for _, cert := range m.certificates {
		if cert.MDMIdentity != cert.X509.Equal(mdmCert) {
			t.Fatal("incorrect active MDM certificate")
		}
	}
	preview, err := m.selected.PreviewProfile(raw)
	if err != nil || !strings.Contains(string(preview.XML), "Changed payload") {
		t.Fatalf("original MDM identity could not decrypt after issuance: %v", err)
	}
}

func marshalTestPlist(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := plist.Marshal(value, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func encryptedSCEPProfile(t *testing.T, cert *x509.Certificate, id, server, subject string) []byte {
	t.Helper()
	payloads := marshalTestPlist(t, []map[string]any{{
		"PayloadType": "com.apple.security.scep", "PayloadVersion": 1, "PayloadUUID": id + "-scep",
		"PayloadIdentifier": id + ".scep", "PayloadDisplayName": id + " certificate",
		"PayloadContent": map[string]any{
			"URL": server, "Subject": [][][]string{{{"CN", subject}}}, "Challenge": "local-scep",
			"Keysize": 2048,
		},
	}})
	encrypted, err := pkcs7.Encrypt(payloads, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	return marshalTestPlist(t, map[string]any{
		"PayloadIdentifier": id, "PayloadType": "Configuration", "PayloadVersion": 1,
		"EncryptedPayloadContent": encrypted,
	})
}

func runTestSCEPServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Bool, *atomic.Pointer[chan struct{}]) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local SCEP CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var failing atomic.Bool
	var blocked atomic.Pointer[chan struct{}]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("operation") {
		case "GetCACaps":
			io.WriteString(w, "POSTPKIOperation\n")
		case "GetCACert":
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Write(ca.Raw)
		case "PKIOperation":
			n := requests.Add(1)
			if failing.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			if gate := blocked.Load(); gate != nil {
				select {
				case <-*gate:
				case <-r.Context().Done():
					return
				}
			}
			message, err := scep.ParsePKIMessage(body)
			if err == nil {
				err = message.DecryptPKIEnvelope(ca, key)
			}
			if err != nil {
				t.Error(err)
				return
			}
			if message.CSRReqMessage.ChallengePassword != "local-scep" {
				t.Error("missing payload challenge")
			}
			csr := message.CSRReqMessage.CSR
			template := &x509.Certificate{
				SerialNumber: big.NewInt(int64(n) + 1), Subject: csr.Subject,
				NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, key)
			if err != nil {
				t.Error(err)
				return
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Error(err)
				return
			}
			reply, err := message.Success(ca, key, cert)
			if err != nil {
				t.Error(err)
				return
			}
			w.Write(reply.Raw)
		default:
			http.Error(w, "unsupported operation", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	return server, &requests, &failing, &blocked
}
