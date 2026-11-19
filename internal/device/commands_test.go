package device

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jessepeterson/mdmb/internal/diagnostics"
	"github.com/jessepeterson/mdmb/protocol"
	"github.com/smallstep/pkcs7"
	bolt "go.etcd.io/bbolt"
	plist "howett.net/plist"
)

func marshalMDMTest(t *testing.T, value any, format int) []byte {
	t.Helper()
	raw, err := plist.Marshal(value, format)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func dispatchTestCommand(t *testing.T, client *MDMClient, raw []byte) any {
	t.Helper()
	var envelope map[string]any
	if err := unmarshalPlist(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	command := dictionaryField(envelope, "Command")
	return client.handleMDMEnvelope(context.Background(), stringField(command, "RequestType"), stringField(envelope, "CommandUUID"), command)
}

func mdmTestDevice(t *testing.T) (*Device, *bolt.DB) {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "test.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	d := New("Test Mac", db)
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}
	return d, db
}

func mdmTestTransport(t *testing.T, d *Device, serverURL string) *MDMClient {
	t.Helper()
	key, cert, err := selfSign()
	if err != nil {
		t.Fatal(err)
	}
	kc := d.SystemKeychain()
	keyItem := NewKeychainItem(kc, ClassKey)
	keyItem.Key = key
	certItem := NewKeychainItem(kc, ClassCertificate)
	certItem.Certificate = cert
	identity := NewKeychainItem(kc, ClassIdentity)
	identity.IdentityKeyUUID, identity.IdentityCertificateUUID = keyItem.UUID, certItem.UUID
	for _, item := range []*KeychainItem{keyItem, certItem, identity} {
		if err := item.Save(); err != nil {
			t.Fatal(err)
		}
	}
	d.MDMIdentityKeychainUUID = identity.UUID
	d.MDMProfileIdentifier = "enrollment"
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{"PayloadType": "Configuration", "PayloadIdentifier": "enrollment",
		"PayloadContent": []map[string]any{{"PayloadType": "com.apple.mdm", "PayloadIdentifier": "mdm",
			"ServerURL": serverURL + "/mdm/ServerURL", "CheckInURL": serverURL + "/mdm/CheckInURL", "SignMessage": true}}}
	if err := d.SystemProfileStore().persistProfile(marshalMDMTest(t, profile, plist.XMLFormat), "enrollment"); err != nil {
		t.Fatal(err)
	}
	c, err := d.MDMClient()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestJamfPollFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/jamf-poll.plist")
	if err != nil {
		t.Fatal(err)
	}
	var fixture []struct {
		HTTPStatus     int
		DeviceRequest  map[string]any
		ServerResponse map[string]any
	}
	if _, err := plist.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	d, db := mdmTestDevice(t)

	var mu sync.Mutex
	step := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if r.Method != http.MethodPut || r.URL.Path != "/mdm/ServerURL" || r.Header.Get("Content-Type") != protocol.MDMMIMEType {
			t.Errorf("unexpected MDM request: %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		verifyMDMSignature(t, r, body)
		var reply map[string]any
		if _, err := plist.Unmarshal(body, &reply); err != nil {
			t.Error(err)
			return
		}
		switch step {
		case 0, 1, 2:
			sample := fixture[step]
			if reply["Status"] != sample.DeviceRequest["Status"] || reply["CommandUUID"] != sample.DeviceRequest["CommandUUID"] {
				t.Errorf("reply %d: %v", step, reply)
			}
			if step == 1 && !reflect.DeepEqual(reply["QueryResponses"], map[string]any{}) {
				t.Errorf("empty query array produced %v", reply["QueryResponses"])
			}
			w.Write(marshalMDMTest(t, sample.ServerResponse, plist.XMLFormat))
		case 3:
			certs, ok := reply["CertificateList"].([]any)
			if !ok || len(certs) != 1 || reply["CommandUUID"] != "test-certs" {
				t.Errorf("certificate reply: %v", reply)
			}
		case 4:
			w.Write(marshalMDMTest(t, map[string]any{"CommandUUID": "malformed",
				"Command": map[string]any{"RequestType": "DeviceInformation"}}, plist.BinaryFormat))
		case 5:
			if reply["CommandUUID"] != "malformed" || reply["Status"] != "CommandFormatError" {
				t.Errorf("malformed reply: %v", reply)
			}
			w.Write(marshalMDMTest(t, map[string]any{"CommandUUID": "account",
				"Command": map[string]any{"RequestType": "DeviceInformation", "Queries": []string{"iTunesStoreAccountIsActive"}}}, plist.BinaryFormat))
		case 6:
			if got := dictionaryField(reply, "QueryResponses")["iTunesStoreAccountIsActive"]; got != false {
				t.Errorf("account flag type/value: %v", got)
			}
			w.Write(marshalMDMTest(t, map[string]any{"CommandUUID": "erase",
				"Command": map[string]any{"RequestType": "EraseDevice"}}, plist.XMLFormat))
		case 7:
			if reply["CommandUUID"] != "erase" || reply["Status"] != "Acknowledged" {
				t.Errorf("erase acknowledgment: %v", reply)
			}
		case 8:
			w.WriteHeader(fixture[4].HTTPStatus)
		default:
			t.Error("unexpected additional poll request")
		}
		step++
	}))
	defer server.Close()
	c := mdmTestTransport(t, d, server.URL)
	for i := 0; i < 2; i++ {
		if err := c.Connect(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := Load(d.UDID, db)
	if err != nil || loaded.MDMProfileIdentifier != d.MDMProfileIdentifier ||
		loaded.MDMIdentityKeychainUUID != d.MDMIdentityKeychainUUID {
		t.Fatalf("erase changed the enrollment: %v", err)
	}
	if _, err := loaded.SystemProfileStore().Raw(d.MDMProfileIdentifier); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected HTTP 500 error, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if step != 9 {
		t.Fatalf("processed %d steps", step)
	}
}

func verifyMDMSignature(t *testing.T, r *http.Request, body []byte) *x509.Certificate {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(r.Header.Get(protocol.MDMSignatureHeader))
	if err != nil {
		t.Error(err)
		return nil
	}
	p7, err := pkcs7.Parse(raw)
	if err != nil {
		t.Error(err)
		return nil
	}
	p7.Content = body
	if err := p7.Verify(); err != nil {
		t.Error(err)
	}
	return p7.GetOnlySigner()
}

func TestCommandSimulationPersistsAndIsolates(t *testing.T) {
	d, db := mdmTestDevice(t)
	other := New("Second Mac", db)
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	config := d.Inventory()
	config.QueryResponses = map[string]any{"BatteryLevel": "85", "IsSupervised": false, "ActiveManagedUsers": []any{"TEST"},
		"LastCloudBackupDate": "2025-10-01T00:00:00Z", "PushToken": "dGVzdA=="}
	config.Applications = []ApplicationMetadata{{Identifier: "com.example.store", Name: "Store App", StoreID: 42, Version: "7"}}
	if err := d.UpdateInventory(config); err != nil {
		t.Fatal(err)
	}

	check := func(d *Device, name, want string, fields map[string]any) map[string]any {
		t.Helper()
		in := map[string]any{"RequestType": name}
		for key, value := range fields {
			in[key] = value
		}
		envelope := map[string]any{"CommandUUID": "test", "Command": in}
		client := &MDMClient{Device: d}
		result := dispatchTestCommand(t, client, marshalMDMTest(t, envelope, plist.BinaryFormat))
		wire, err := PlistReader(result)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		raw, _ := io.ReadAll(wire)
		if _, err := plist.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["Status"] != want || decoded["CommandUUID"] != "test" || decoded["UDID"] != d.UDID {
			t.Fatalf("%s: %v", name, decoded)
		}
		return decoded
	}

	_, cert, err := selfSign()
	if err != nil {
		t.Fatal(err)
	}
	profile := marshalMDMTest(t, map[string]any{"PayloadIdentifier": "test.profile", "PayloadType": "Configuration", "PayloadUUID": "TEST-PROFILE",
		"PayloadVersion": 1, "PayloadContent": []map[string]any{{"PayloadType": "com.apple.security.root", "PayloadContent": cert.Raw}}}, plist.BinaryFormat)
	for i := 0; i < 2; i++ {
		check(d, "InstallProfile", "Acknowledged", map[string]any{"Payload": profile})
		check(d, "InstallApplication", "Acknowledged", map[string]any{"iTunesStoreID": 42})
	}
	check(d, "InstallEnterpriseApplication", "Acknowledged", map[string]any{"InstallAsManaged": true,
		"Manifest": map[string]any{"items": []map[string]any{{"metadata": map[string]any{"bundle-identifier": "com.example.pkg", "bundle-version": "1", "title": "Package App"}}}}})
	check(d, "InstallApplication", "Error", map[string]any{"iTunesStoreID": 17})
	check(d, "RemoveApplication", "CommandFormatError", map[string]any{"Identifier": false})
	settings := check(d, "Settings", "Acknowledged", map[string]any{"Settings": []map[string]any{
		{"Item": "ApplicationConfiguration", "Identifier": "com.example.store", "Configuration": map[string]any{"enabled": false, "count": 0}},
		{"Item": "ApplicationAttributes", "Identifier": "com.example.store", "Attributes": map[string]any{"Removable": false}},
		{"Item": "MDMOptions", "MDMOptions": map[string]any{"BootstrapTokenAllowed": true}},
		{"Item": "TimeZone", "TimeZone": "Europe/Moscow"},
		{"Item": "Wallpaper", "Where": 1, "Image": []byte("invalid")},
	}})
	if results := settings["Settings"].([]any); len(results) != 5 || results[4].(map[string]any)["Status"] != "Error" {
		t.Fatalf("settings: %v", settings)
	}
	check(d, "EraseDevice", "Acknowledged", nil)
	path := db.Path()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	d, err = Load(d.UDID, db)
	if err != nil {
		t.Fatal(err)
	}
	other, err = Load(other.UDID, db)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := d.SystemProfileStore().Raw("test.profile")
	if err != nil || !bytes.Equal(stored, profile) {
		t.Fatal("profile bytes did not survive an EraseDevice simulation")
	}
	for _, fixture := range []struct {
		cmd, field string
		count      int
	}{
		{"ProfileList", "ProfileList", 1}, {"CertificateList", "CertificateList", 1}, {"InstalledApplicationList", "InstalledApplicationList", 2},
	} {
		if got := check(d, fixture.cmd, "Acknowledged", nil)[fixture.field].([]any); len(got) != fixture.count {
			t.Fatalf("%s: %v", fixture.cmd, got)
		}
		if got := check(other, fixture.cmd, "Acknowledged", nil)[fixture.field].([]any); len(got) != 0 {
			t.Fatalf("state leaked across devices: %v", got)
		}
	}
	if managed := check(d, "ManagedApplicationList", "Acknowledged", nil)["ManagedApplicationList"].(map[string]any); len(managed) != 2 {
		t.Fatalf("managed apps: %v", managed)
	}
	for _, tc := range []struct{ command, collection, field string }{
		{"ManagedApplicationConfiguration", "ApplicationConfigurations", "Configuration"},
		{"ManagedApplicationAttributes", "ApplicationAttributes", "Attributes"},
	} {
		result := check(d, tc.command, "Acknowledged", map[string]any{"Identifiers": []string{"com.example.store"}})[tc.collection].([]any)
		if len(result) != 1 || dictionaryField(result[0].(map[string]any), tc.field) == nil {
			t.Fatal(result)
		}
	}
	info := check(d, "DeviceInformation", "Acknowledged", map[string]any{"Queries": []string{
		"BatteryLevel", "IsSupervised", "ActiveManagedUsers", "LastCloudBackupDate", "PushToken", "TimeZone", "MDMOptions"}})["QueryResponses"].(map[string]any)
	if len(info) != 7 || info["BatteryLevel"] != 0.85 || info["IsSupervised"] != false || info["TimeZone"] != "Europe/Moscow" ||
		!bytes.Equal(info["PushToken"].([]byte), []byte("test")) {
		t.Fatalf("typed inventory: %v", info)
	}
	check(d, "RemoveApplication", "Acknowledged", map[string]any{"Identifier": "com.example.store"})
	check(d, "RemoveProfile", "Acknowledged", map[string]any{"Identifier": "test.profile"})
	if certs := check(d, "CertificateList", "Acknowledged", map[string]any{"ManagedOnly": true})["CertificateList"].([]any); len(certs) != 0 {
		t.Fatal("certificate remained after its profile was removed")
	}
	for _, fixture := range []struct {
		name   string
		fields map[string]any
	}{
		{"RestartDevice", nil}, {"ShutDownDevice", nil}, {"DeviceLock", nil}, {"ClearPasscode", map[string]any{"UnlockToken": []byte("test")}},
		{"SetRecoveryLock", map[string]any{"NewPassword": ""}}, {"AccountConfiguration", nil}, {"DeleteUser", map[string]any{"UserName": "test"}},
		{"SetAutoAdminPassword", map[string]any{"GUID": "test", "passwordHash": []byte("test")}},
		{"InstallMedia", map[string]any{"iTunesStoreID": 1, "MediaType": "Book"}}, {"RequestMirroring", map[string]any{"DestinationName": "test"}},
		{"StopMirroring", nil},
	} {
		check(d, fixture.name, "Acknowledged", fixture.fields)
	}
	check(d, "WipeDevice", "Error", nil)
}

func TestDeclarativeSynchronizationAndRetry(t *testing.T) {
	d, _ := mdmTestDevice(t)
	var mu sync.Mutex
	stage, standard := 0, []string{}
	var signedBy *x509.Certificate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		if signer := verifyMDMSignature(t, r, body); signer == nil || !signer.Equal(signedBy) {
			t.Error("request did not use the enrollment identity")
		}
		var req map[string]any
		if _, err := plist.Unmarshal(body, &req); err != nil {
			t.Error(err)
			return
		}
		if r.URL.Path == "/mdm/ServerURL" {
			standard = append(standard, "poll:"+stringField(req, "Status"))
			if req["Status"] != "Idle" {
				return
			}
			command := map[string]any{"RequestType": "DeclarativeManagement"}
			if stage != 1 {
				token := 1
				if stage >= 2 {
					token = 2
				}
				command["Data"] = []byte(fmt.Sprintf(`{"SyncTokens":{"DeclarationsToken":"t%d"}}`, token))
			}
			w.Write(marshalMDMTest(t, map[string]any{"CommandUUID": "ddm", "Command": command}, plist.XMLFormat))
			return
		}
		if r.URL.Path != "/mdm/CheckInURL" || r.Header.Get("Content-Type") != protocol.CheckInMIMEType ||
			req["MessageType"] != "DeclarativeManagement" || req["UDID"] != d.UDID {
			t.Errorf("check-in did not use the expected route and envelope: %v", req)
		}
		endpoint := stringField(req, "Endpoint")
		standard = append(standard, endpoint)
		switch endpoint {
		case "tokens":
			io.WriteString(w, `{"SyncTokens":{"DeclarationsToken":"t1"}}`)
		case "declaration-items":
			tok := 1
			var items = `{"Identifier":"first","ServerToken":"v1"},{"Identifier":"removed","ServerToken":"v1"}`
			if stage >= 2 {
				tok = 2
				items = `{"Identifier":"first","ServerToken":"v2"},{"Identifier":"missing","ServerToken":"v1"}`
			}
			fmt.Fprintf(w, `{"DeclarationsToken":"t%d","Declarations":{"Activations":[],"Assets":[],"Management":[],"Configurations":[%s]}}`, tok, items)
		case "declaration/configuration/first":
			if stage == 2 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			version := 1
			if stage >= 3 {
				version = 2
			}
			fmt.Fprintf(w, `{"Identifier":"first","ServerToken":"v%d","Type":"com.apple.configuration.legacy","Payload":{}}`, version)
		case "declaration/configuration/removed":
			io.WriteString(w, `{"Identifier":"removed","ServerToken":"v1","Type":"com.apple.configuration.legacy","Payload":{}}`)
		case "declaration/configuration/missing":
			w.WriteHeader(http.StatusNotFound)
		case "status":
			data, _ := req["Data"].([]byte)
			if !bytes.Contains(data, []byte(`"active":false`)) || !bytes.Contains(data, []byte(`"Errors":[]`)) || (stage >= 3 && bytes.Contains(data, []byte("removed"))) {
				t.Errorf("unexpected status payload: %s", data)
			}
			if stage == 0 {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		default:
			t.Errorf("unexpected check-in endpoint %q", endpoint)
		}
	}))
	defer server.Close()
	c := mdmTestTransport(t, d, server.URL)
	mu.Lock()
	signedBy = c.IdentityCertificate
	mu.Unlock()
	desired := [][]string{
		{"declaration-items", "declaration/configuration/first", "declaration/configuration/removed", "status"},
		{"tokens", "status"},
		{"declaration-items", "declaration/configuration/first"},
		{"declaration-items", "declaration/configuration/first", "declaration/configuration/missing", "status"},
		{},
	}
	for i, endpoints := range desired {
		mu.Lock()
		stage, standard = i, nil
		mu.Unlock()
		var log bytes.Buffer
		if err := c.Connect(diagnostics.WithOutput(context.Background(), &log)); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		want := append([]string{"poll:Idle", "poll:Acknowledged"}, endpoints...)
		if !reflect.DeepEqual(standard, want) {
			t.Errorf("stage %d: got %v, want %v", i, standard, want)
		}
		mu.Unlock()
		state, err := c.loadDeclarativeState()
		if err != nil {
			t.Fatal(err)
		}
		token := "t1"
		if i >= 3 {
			token = "t2"
		}
		if state.Token != token || (i == 0) != state.StatusPending {
			t.Fatalf("stage %d: %s, pending %v, log %s", i, state.Token, state.StatusPending, &log)
		}
		if i >= 3 && len(state.Declarations["configuration"]) != 1 {
			t.Fatal("removed declarations remain in snapshot")
		}
	}
}
