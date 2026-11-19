package device

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestRefreshJamfPolicies(t *testing.T) {
	d, db := mdmTestDevice(t)
	var calls atomic.Int32
	clientKey := make(chan *rsa.PublicKey, 1)
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/jamf/client" || r.Method != http.MethodPost || (r.Header.Get("Content-Type") != "application/xml; charset=utf-8" || r.UserAgent() != "Mac OS X "+d.OSVersion+";") {
			t.Errorf("unexpected request %s %s (%s)", r.Method, r.URL, r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		signature, err := base64.StdEncoding.DecodeString(r.Header.Get("JAMF-Device-Sig"))
		if err != nil || r.Header.Get("JAMF-Device-Alg") != "SHA256withRSA" {
			t.Errorf("unexpected Jamf signature headers: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := <-clientKey
		clientKey <- key
		digest := sha256.Sum256(body)
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
			t.Errorf("invalid check-in signature: %v", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var request struct {
			XMLName xml.Name `xml:"http://www.jamfsoftware.com/JAMFMessage jamfMessage"`
			UDID    string   `xml:"device>uuid"`
			Serial  string   `xml:"device>serialNumber"`
			ID      string   `xml:"content>uuid"`
			Command string   `xml:"content>commandType"`
			Check   struct {
				Trigger string `xml:"http://www.jamfsoftware.com/JAMFMessage trigger"`
				Day     string `xml:"http://www.jamfsoftware.com/JAMFMessage day"`
			} `xml:"content>commandData>checkForPolicies"`
		}
		if err := xml.Unmarshal(body, &request); err != nil || request.ID == "" || request.UDID != d.UDID || request.Serial != d.Serial ||
			request.Command != "com.jamfsoftware.jamf.checkforpoliciesrequest" || request.Check.Trigger != "CLIENT_CHECKIN" ||
			len(request.Check.Day) != 3 {
			t.Errorf("unexpected check-in body %s: %v", body, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var policies string
		switch calls.Add(1) {
		case 1, 2, 3:
			name := "Before.sh"
			if calls.Load() == 3 {
				name = "After.sh"
			}
			policies = fmt.Sprintf(`<policy><id>17</id><name>Setup</name>
				<packages><package><name>Tools</name><action>Install</action></package></packages>
				<scripts><script><filename>%s</filename><priority>Before</priority>
				<parameters><parameter>hidden-config</parameter></parameters><contents>hidden-source</contents></script></scripts>
				<printers><printer><name>Office</name><action>Install</action></printer></printers>
				<maintenanceSettings><updateInventory>true</updateInventory></maintenanceSettings>
				<rebootSettings><userRebootIfRequired>true</userRebootIfRequired><recoveryKey>hidden-key</recoveryKey></rebootSettings>
				</policy>`, name)
		case 4:
			// Successful empty response.
		case 5:
			w.WriteHeader(http.StatusForbidden)
			return
		case 6:
			fmt.Fprint(w, "<invalid")
			return
		case 7:
			close(started)
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<j:jamfMessage xmlns:j="http://www.jamfsoftware.com/JAMFMessage">
			<content><uuid>%s</uuid><commandType>com.jamfsoftware.jamf.checkforpoliciesresponse</commandType>
			<status><code>0</code></status><commandData><checkForPolicies><policies>%s</policies>
			</checkForPolicies></commandData></content></j:jamfMessage>`, request.ID, policies)
	}))
	defer server.Close()
	client := mdmTestTransport(t, d, server.URL+"/jamf")
	identity := testJamfFrameworkIdentity(t, d.UDID)
	clientKey <- identity.certificate.PublicKey.(*rsa.PublicKey)
	transport := server.Client().Transport
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := client.refreshJamfPolicies(ctx, nil, transport); err == nil {
		t.Fatal("refresh accepted a missing Framework identity")
	}
	wrongIdentity := testJamfFrameworkIdentity(t, "another-device")
	if _, err := client.refreshJamfPolicies(ctx, wrongIdentity, transport); err == nil {
		t.Fatal("refresh accepted an identity registered to another device")
	}
	if calls.Load() != 0 {
		t.Fatal("refresh reached Jamf without a matching Framework identity")
	}

	for i, want := range []int{1, 1, 1, 0} {
		count, err := client.refreshJamfPolicies(ctx, identity, transport)
		if err != nil || count != want {
			t.Fatalf("refresh %d: count %d, error %v", i+1, count, err)
		}
	}
	if _, err := client.refreshJamfPolicies(ctx, identity, transport); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("expected authentication error, got %v", err)
	}
	if _, err := client.refreshJamfPolicies(ctx, identity, transport); err == nil {
		t.Fatal("malformed response succeeded")
	}
	cancelCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	done := make(chan error, 1)
	go func() {
		_, err := client.refreshJamfPolicies(cancelCtx, identity, transport)
		done <- err
	}()
	select {
	case <-started:
		cancelRequest()
	case <-ctx.Done():
		t.Fatal("cancel test request did not reach the server")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}

	dbPath := db.Path()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.View(func(tx *bolt.Tx) error {
		data := string(BucketGet(tx, jamfPolicyBucket, d.UDID))
		if strings.Contains(data, "hidden-") {
			t.Fatal("stored sensitive response fields")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(d.UDID, reopened)
	if err != nil {
		t.Fatal(err)
	}
	history, err := reloaded.JamfPolicies()
	if err != nil || len(history) != 1 || len(history[0].Versions) != 2 {
		t.Fatalf("expected exactly two saved versions, got %+v (%v)", history, err)
	}
	latest, previous := history[0].Versions[0], history[0].Versions[1]
	if len(latest.Policy.Scripts) != 1 || len(previous.Policy.Scripts) != 1 ||
		latest.Policy.Scripts[0].Filename != "After.sh" || previous.Policy.Scripts[0].Filename != "Before.sh" ||
		!latest.LastSeen.After(previous.LastSeen) || !latest.Policy.Maintenance.UpdateInventory ||
		!latest.Policy.Restart.WithUserIfRequired || len(latest.Policy.Printers) != 1 || len(latest.Policy.Packages) != 1 {
		t.Fatalf("unexpected policy history %+v", history)
	}
}

func testJamfFrameworkIdentity(t *testing.T, udid string) *JamfFrameworkIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: udid},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "framework.der")
	keyPath := filepath.Join(dir, "framework-key.pem")
	if err := os.WriteFile(certPath, der, 0600); err != nil {
		t.Fatal(err)
	}
	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadJamfFrameworkIdentity(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
