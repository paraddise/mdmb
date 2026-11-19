package tui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/jessepeterson/mdmb/internal/device"
	"github.com/smallstep/pkcs7"
	bolt "go.etcd.io/bbolt"
	plist "howett.net/plist"
)

func openTestDB(t *testing.T, path string) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func createDevice(t *testing.T, db *bolt.DB, name string) *device.Device {
	t.Helper()
	d := device.New(name, db)
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestInventoryEditor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db := openTestDB(t, path)
	m := newModel(db, context.Background())
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	if m.selected == nil || m.screen != deviceScreen {
		t.Fatal("creating a device should open its details")
	}
	id := m.selected.UDID
	other := createDevice(t, db, "Second device")
	m.openEditor()
	var fields device.Inventory
	if err := json.Unmarshal([]byte(m.initialJSON), &fields); err != nil {
		t.Fatal(err)
	}
	fields.ComputerName = "Edited"
	fields.QueryResponses = map[string]any{"CustomQuery": "", "DeviceName": "MDM name"}
	disabled, zero := false, 0
	fields.SecurityInfo.PasscodePresent = &disabled
	fields.SecurityInfo.HardwareEncryption = &zero
	jsonBytes, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	m.editor.SetValue(string(jsonBytes))
	m.saveInventory()
	if m.screen != deviceScreen {
		t.Fatal(m.status)
	}

	m.openEditor()
	for _, invalid := range []string{
		`{"Serial":"new","UDID":"other"}`,
		`{"Serial":"new","QueryResponses":{"x":null}}`,
		`{"Serial":"new","SecurityInfo":{"PasscodePresent":0}}`,
		`{"Serial":""}`,
		`{"Serial":"new"} {}`,
	} {
		m.editor.SetValue(invalid)
		m.saveInventory()
		if m.screen != editorScreen || m.editor.Value() != invalid {
			t.Fatalf("invalid JSON lost or saved: %s", invalid)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openTestDB(t, path)
	d, err := device.Load(id, db)
	if err != nil {
		t.Fatal(err)
	}
	if d.ComputerName != "Edited" || d.Serial != fields.Serial || d.QueryResponses()["DeviceName"] != "MDM name" ||
		d.EffectiveSecurityInfo()["PasscodePresent"] != false || d.EffectiveSecurityInfo()["HardwareEncryptionCaps"] != 0 {
		t.Fatalf("wrong persisted inventory: %+v", d.Inventory())
	}
	second, err := device.Load(other.UDID, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := second.QueryResponses()["CustomQuery"]; ok || second.EffectiveSecurityInfo()["PasscodePresent"] != true {
		t.Fatal("device overrides leaked into a preexisting record")
	}
	fields = d.Inventory()
	fields.InventoryOverrides = device.InventoryOverrides{}
	if err := d.UpdateInventory(fields); err != nil {
		t.Fatal(err)
	}
	if d.QueryResponses()["DeviceName"] != "Edited" || d.EffectiveSecurityInfo()["HardwareEncryptionCaps"] != 2 {
		t.Fatal("clearing overrides should restore defaults")
	}
}

func TestPollAndExportProfile(t *testing.T) {
	db := openTestDB(t, filepath.Join(t.TempDir(), "test.db"))
	d := createDevice(t, db, "MDM device")
	inventory := d.Inventory()
	inventory.QueryResponses = map[string]any{"DeviceName": "MDM custom name", "CustomQuery": ""}
	disabled, zero := false, 0
	inventory.SecurityInfo.ActivationLockEnabled = &disabled
	inventory.SecurityInfo.HardwareEncryption = &zero
	if err := d.UpdateInventory(inventory); err != nil {
		t.Fatal(err)
	}

	config := map[string]any{
		"PayloadIdentifier": "test.profile", "PayloadDisplayName": "Test Profile",
		"PayloadType": "Configuration", "PayloadUUID": "test-profile", "PayloadVersion": 1,
		"PayloadContent": []map[string]any{{
			"PayloadType": "test.unknown", "PayloadIdentifier": "test.payload", "PayloadUUID": "test-payload",
			"PayloadVersion": 1, "CustomSetting": "retained",
		}},
	}
	profile, err := plist.Marshal(config, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	waiting, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var response struct {
			Status         string
			CommandUUID    string
			QueryResponses map[string]any
			SecurityInfo   map[string]any
		}
		if _, err := plist.Unmarshal(body, &response); err != nil {
			t.Error(err)
			return
		}
		var cmd map[string]any
		id := response.CommandUUID
		switch id {
		case "":
			cmd = map[string]any{"RequestType": "DeviceInformation", "Queries": []string{"DeviceName", "CustomQuery", "IsActivationLockEnabled"}}
			id = "inventory"
		case "inventory":
			if v, ok := response.QueryResponses["CustomQuery"]; !ok || v != "" || response.QueryResponses["DeviceName"] != "MDM custom name" || response.QueryResponses["IsActivationLockEnabled"] != false {
				t.Errorf("inventory: %+v", response)
			}
			cmd, id = map[string]any{"RequestType": "SecurityInfo"}, "security"
		case "security":
			if response.SecurityInfo["HardwareEncryptionCaps"] != uint64(0) {
				t.Errorf("security: %+v", response)
			}
			cmd, id = map[string]any{"RequestType": "InstallProfile", "Payload": profile}, "install"
		case "install":
			if response.Status != "Acknowledged" {
				t.Errorf("install: %+v", response)
			}
			close(waiting)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		default:
			t.Errorf("unexpected command UUID: %q", id)
			return
		}
		data, err := plist.Marshal(map[string]any{"CommandUUID": id, "Command": cmd}, plist.BinaryFormat)
		if err != nil {
			t.Error(err)
			return
		}
		w.Write(data)
	}))
	defer server.Close()
	defer close(release)
	seedEnrollment(t, db, d, server.URL)

	m := newModel(db, context.Background())
	m.openDevice(d.UDID)
	poll := m.startPoll()
	if poll == nil {
		t.Fatal(m.status)
	}
	finished := make(chan pollResult, 1)
	go func() { finished <- poll().(pollResult) }()
	select {
	case <-waiting:
	case early := <-finished:
		t.Fatalf("poll ended early: %+v", early)
	case <-time.After(5 * time.Second):
		t.Fatal("poll didn't reach InstallProfile")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	var result pollResult
	select {
	case result = <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("poll didn't cancel")
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("poll: %v", result.err)
	}
	m.finishPoll(result)
	if len(m.profiles) != 2 || !strings.Contains(m.diagnostics, "test.unknown") {
		t.Fatalf("partially processed queue wasn't reflected: %v, %s", m.profiles, m.diagnostics)
	}
	m.profileIndex = 1
	m.openProfile()
	if m.screen != profileScreen || !strings.Contains(m.viewText, "CustomSetting") || !strings.Contains(m.viewText, "Payloads (1)") {
		t.Fatalf("profile view: %s / %s", m.status, m.viewText)
	}
	dest := filepath.Join(t.TempDir(), "test.mobileconfig")
	m.exportPath.SetValue(dest)
	m.exportProfile()
	exported, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(exported, profile) {
		t.Fatalf("export changed original bytes: %v", err)
	}
	if err := writeProfile(dest, []byte("replacement")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("export should reject existing files: %v", err)
	}
}

func seedEnrollment(t *testing.T, db *bolt.DB, d *device.Device, serverURL string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	kc := d.SystemKeychain()
	privateKey := device.NewKeychainItem(kc, device.ClassKey)
	privateKey.Key = key
	cert := device.NewKeychainItem(kc, device.ClassCertificate)
	cert.Certificate = certificate
	identity := device.NewKeychainItem(kc, device.ClassIdentity)
	identity.IdentityKeyUUID, identity.IdentityCertificateUUID = privateKey.UUID, cert.UUID
	for _, item := range []*device.KeychainItem{privateKey, cert, identity} {
		if err := item.Save(); err != nil {
			t.Fatal(err)
		}
	}
	d.MDMIdentityKeychainUUID = identity.UUID
	d.MDMProfileIdentifier = "enrollment"
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}
	enrollment, err := plist.Marshal(map[string]any{
		"PayloadIdentifier": "enrollment", "PayloadType": "Configuration", "PayloadVersion": 1,
		"PayloadContent": []map[string]any{{
			"PayloadIdentifier": "enrollment.mdm", "PayloadType": "com.apple.mdm", "PayloadVersion": 1,
			"ServerURL": serverURL, "SignMessage": true,
		}},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return device.BucketPutOrDelete(tx, "profiles", d.UDID+"_enrollment", enrollment)
	}); err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestEncryptedProfilePreview(t *testing.T) {
	db := openTestDB(t, filepath.Join(t.TempDir(), "test.db"))
	d := createDevice(t, db, "Encrypted device")
	cert := seedEnrollment(t, db, d, "https://localhost")
	other := createDevice(t, db, "Other device")
	seedEnrollment(t, db, other, "https://localhost")
	unenrolled := createDevice(t, db, "Unenrolled device")
	payloads := []map[string]any{{
		"PayloadType": "test.unknown", "PayloadIdentifier": "test.encrypted.payload",
		"PayloadVersion": 1, "CustomSetting": "decrypted value",
	}}
	plain, err := plist.Marshal(payloads, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	// Apple profiles can carry an XML array fragment inside the CMS envelope.
	start, end := bytes.Index(plain, []byte("<array>")), bytes.LastIndex(plain, []byte("</array>"))
	if start < 0 || end < start {
		t.Fatal("missing XML payload array")
	}
	plain = plain[start : end+len("</array>")]
	encrypted, err := pkcs7.Encrypt(plain, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := plist.Marshal(map[string]any{
		"PayloadIdentifier": "test.encrypted", "PayloadType": "Configuration", "PayloadVersion": 1,
		"EncryptedPayloadContent": encrypted,
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.InstallProfile(context.Background(), profile); err != nil {
		t.Fatal(err)
	}

	m := newModel(db, context.Background())
	m.openDevice(d.UDID)
	m.reloadProfiles("test.encrypted")
	if !strings.Contains(m.profilesView(), "Encrypted") {
		t.Fatal("encrypted profile should be labeled in the list")
	}
	m.openProfile()
	if m.screen != profileScreen || !strings.Contains(m.viewText, "Payloads (1)") ||
		!strings.Contains(m.viewText, "test.encrypted.payload") ||
		!strings.Contains(m.viewText, "decrypted value") || strings.Contains(m.viewText, "EncryptedPayloadContent") {
		t.Fatal("profile view should display the decrypted payloads")
	}
	dest := filepath.Join(t.TempDir(), "encrypted.mobileconfig")
	m.exportPath.SetValue(dest)
	m.exportProfile()
	raw, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(raw, profile) {
		t.Fatalf("export must preserve the ciphertext: %v", err)
	}
	for _, deviceWithoutKey := range []*device.Device{other, unenrolled} {
		preview, err := deviceWithoutKey.PreviewProfile(profile)
		if err == nil || !preview.Encrypted || len(preview.XML) != 0 {
			t.Fatal("preview should fail when the matching identity is unavailable")
		}
	}
}
