package device

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
	plist "howett.net/plist"
)

func TestInterruptedSCEPRequiresManualRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interrupted.db")
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close() }()
	d := New("Interrupted device", db)
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := plist.Marshal(map[string]any{
		"PayloadIdentifier": "profile",
		"PayloadContent": []map[string]any{{
			"PayloadType": scepPayloadType, "PayloadIdentifier": "scep",
			"PayloadContent": map[string]any{"URL": "https://localhost"},
		}},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SystemProfileStore().persistProfile(raw, "profile"); err != nil {
		t.Fatal(err)
	}
	rows, err := d.SCEPPayloads("profile")
	if err != nil || len(rows) != 1 {
		t.Fatalf("SCEP payloads: %v %v", rows, err)
	}
	version := rows[0].Version
	if err := db.Update(func(tx *bolt.Tx) error {
		return saveSCEPStatus(tx, d.scepStateKey("profile", version), SCEPStatus{State: "Enrolling"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Load(d.UDID, db)
	if err != nil {
		t.Fatal(err)
	}
	d.autoEnrollProfile(context.Background(), "profile")
	rows, err = d.SCEPPayloads("profile")
	if err != nil || len(rows) != 1 || rows[0].Status.State != "Interrupted" {
		t.Fatalf("interrupted state after poll: %v %v", rows, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	status, err := d.EnrollSCEP(ctx, "profile", version)
	if !errors.Is(err, context.Canceled) || status.State != "Cancelled" {
		t.Fatalf("manual retry of interrupted state: %+v %v", status, err)
	}
}
