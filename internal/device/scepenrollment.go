package device

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	groob "github.com/groob/plist"
	"github.com/jessepeterson/cfgprofiles"
	"github.com/jessepeterson/mdmb/internal/diagnostics"
	bolt "go.etcd.io/bbolt"
	plist "howett.net/plist"
)

const (
	scepPayloadType = "com.apple.security.scep"
	autoSCEPBucket  = "device_auto_scep_enroll"
	scepStateBucket = "device_scep_enrollments"
)

type SCEPStatus struct {
	State           string
	CertificateUUID string
	IdentityUUID    string
	Error           string
}

type SCEPPayload struct {
	Version string
	Name    string
	Host    string
	Status  SCEPStatus

	data []byte
}

func (d *Device) AutoSCEPEnroll() (enabled bool, err error) {
	err = d.boltDB.View(func(tx *bolt.Tx) error {
		enabled = BucketGetString(tx, autoSCEPBucket, d.UDID) == "1"
		return nil
	})
	return
}

func (d *Device) SetAutoSCEPEnroll(enabled bool) error {
	value := ""
	if enabled {
		value = "1"
	}
	return d.boltDB.Update(func(tx *bolt.Tx) error {
		return BucketPutOrDeleteString(tx, autoSCEPBucket, d.UDID, value)
	})
}

func (d *Device) scepStateKey(profileID, version string) string {
	// Hash the tuple to avoid delimiter ambiguity and Bolt's key size limit.
	tuple, _ := json.Marshal([3]string{d.UDID, profileID, version})
	return fmt.Sprintf("%x", sha256.Sum256(tuple))
}

func loadSCEPStatus(tx *bolt.Tx, key string) (status SCEPStatus, err error) {
	if raw := BucketGet(tx, scepStateBucket, key); raw != nil {
		err = json.Unmarshal(raw, &status)
	}
	return
}

func saveSCEPStatus(tx *bolt.Tx, key string, status SCEPStatus) error {
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return BucketPutOrDelete(tx, scepStateBucket, key, raw)
}

func (d *Device) SCEPPayloads(profileID string) ([]SCEPPayload, error) {
	raw, err := d.SystemProfileStore().Raw(profileID)
	if err != nil {
		return nil, err
	}
	profile, _, err := d.decodedProfile(raw)
	if err != nil {
		return nil, err
	}
	content, _ := profile["PayloadContent"].([]any)
	var bootstrapUUID string
	if profileID == d.MDMProfileIdentifier && d.MDMIdentityKeychainUUID != "" {
		for _, item := range content {
			payload, _ := item.(map[string]any)
			if payload["PayloadType"] == "com.apple.mdm" {
				bootstrapUUID, _ = payload["IdentityCertificateUUID"].(string)
			}
		}
	}
	var rows []SCEPPayload
	for _, item := range content {
		payload, _ := item.(map[string]any)
		if payload["PayloadType"] != scepPayloadType {
			continue
		}
		data, err := plist.Marshal(payload, plist.XMLFormat)
		if err != nil {
			return nil, err
		}
		row := SCEPPayload{Version: fmt.Sprintf("%x", sha256.Sum256(data)), data: data}
		row.Name, _ = payload["PayloadDisplayName"].(string)
		if row.Name == "" {
			row.Name, _ = payload["PayloadIdentifier"].(string)
		}
		if row.Name == "" {
			row.Name = "SCEP payload"
		}
		parameters, _ := payload["PayloadContent"].(map[string]any)
		endpoint, _ := parameters["URL"].(string)
		if parsed, err := url.Parse(endpoint); err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") {
			row.Host = parsed.Host
		}
		if bootstrapUUID != "" && payload["PayloadUUID"] == bootstrapUUID {
			identity, err := LoadKeychainItem(d.SystemKeychain(), d.MDMIdentityKeychainUUID)
			if err != nil {
				return nil, err
			}
			row.Status = SCEPStatus{State: "Issued", IdentityUUID: identity.UUID, CertificateUUID: identity.IdentityCertificateUUID}
		}
		rows = append(rows, row)
	}
	err = d.boltDB.View(func(tx *bolt.Tx) error {
		for i := range rows {
			if rows[i].Status.State != "" {
				continue
			}
			row := &rows[i]
			var err error
			row.Status, err = loadSCEPStatus(tx, d.scepStateKey(profileID, row.Version))
			if err != nil {
				return err
			}
			switch row.Status.State {
			case "":
				row.Status.State = "Not enrolled"
			case "Enrolling":
				if _, active := scepFlights.Load(scepFlightKey{d.boltDB, d.scepStateKey(profileID, row.Version)}); !active {
					row.Status.State = "Interrupted"
				}
			}
		}
		return nil
	})
	return rows, err
}

type scepFlightKey struct {
	db  *bolt.DB
	key string
}

type scepFlight struct {
	done   chan struct{}
	status SCEPStatus
	err    error
}

var scepFlights sync.Map

func (d *Device) EnrollSCEP(ctx context.Context, profileID, version string) (SCEPStatus, error) {
	return d.enrollSCEP(ctx, profileID, version, true)
}

func (d *Device) enrollSCEP(ctx context.Context, profileID, version string, manual bool) (status SCEPStatus, err error) {
	key := d.scepStateKey(profileID, version)
	flightKey := scepFlightKey{d.boltDB, key}
	flight := &scepFlight{done: make(chan struct{})}
	if existing, loaded := scepFlights.LoadOrStore(flightKey, flight); loaded {
		other := existing.(*scepFlight)
		select {
		case <-other.done:
			return other.status, other.err
		case <-ctx.Done():
			return SCEPStatus{}, ctx.Err()
		}
	}
	defer func() {
		flight.status, flight.err = status, err
		close(flight.done)
		scepFlights.Delete(flightKey)
	}()

	// Always use the identity currently recorded in the database.
	d, err = Load(d.UDID, d.boltDB)
	if err != nil {
		return status, err
	}
	rows, err := d.SCEPPayloads(profileID)
	if err != nil {
		return status, err
	}
	var selected SCEPPayload
	for _, row := range rows {
		if row.Version == version {
			if row.Status.State == "Issued" {
				return row.Status, nil
			}
			selected = row
			break
		}
	}
	if selected.Version == "" {
		return status, errors.New("SCEP payload changed or no longer exists")
	}

	started := false
	err = d.boltDB.Update(func(tx *bolt.Tx) error {
		var err error
		status, err = loadSCEPStatus(tx, key)
		if err != nil || status.State == "Issued" || (status.State != "" && !manual) {
			return err
		}
		started = true
		return saveSCEPStatus(tx, key, SCEPStatus{State: "Enrolling"})
	})
	if err != nil || !started {
		return status, err
	}

	status, err = d.issueSCEP(ctx, profileID, key, selected)
	if err != nil {
		status = SCEPStatus{State: "Failed", Error: err.Error()}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status.State = "Cancelled"
		}
		saveErr := d.boltDB.Update(func(tx *bolt.Tx) error { return saveSCEPStatus(tx, key, status) })
		err = errors.Join(err, saveErr)
	}
	return status, err
}

func (d *Device) issueSCEP(ctx context.Context, profileID, stateKey string, row SCEPPayload) (SCEPStatus, error) {
	var payload cfgprofiles.SCEPPayload
	if err := groob.Unmarshal(row.data, &payload); err != nil {
		return SCEPStatus{}, fmt.Errorf("invalid SCEP payload: %w", err)
	}
	if row.Host == "" {
		return SCEPStatus{}, errors.New("SCEP payload requires an HTTP or HTTPS server URL")
	}
	key, cert, err := d.requestSCEPCertificate(ctx, &payload)
	if err != nil {
		return SCEPStatus{}, err
	}

	kc := d.SystemKeychain()
	keyItem := NewKeychainItem(kc, ClassKey)
	keyItem.Key = key
	certItem := NewKeychainItem(kc, ClassCertificate)
	certItem.Certificate = cert
	identity := NewKeychainItem(kc, ClassIdentity)
	identity.IdentityKeyUUID, identity.IdentityCertificateUUID = keyItem.UUID, certItem.UUID
	result := SCEPStatus{State: "Issued", CertificateUUID: certItem.UUID, IdentityUUID: identity.UUID}
	err = d.boltDB.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, item := range []*KeychainItem{keyItem, certItem, identity} {
			if err := item.save(tx); err != nil {
				return err
			}
		}
		if BucketGetString(tx, managedProfileBucket, d.UDID+"_"+profileID) == "1" {
			if err := BucketPutOrDeleteString(tx, managedCertificateBucket, certItem.boltKey(), "1"); err != nil {
				return err
			}
		}
		return saveSCEPStatus(tx, stateKey, result)
	})
	return result, err
}

func (d *Device) autoEnrollProfile(ctx context.Context, profileID string) {
	rows, err := d.SCEPPayloads(profileID)
	if err != nil {
		diagnostics.Printf(ctx, os.Stderr, "SCEP profile %s: %v\n", profileID, err)
		return
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		if row.Status.State != "Not enrolled" {
			continue
		}
		attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, err := d.enrollSCEP(attempt, profileID, row.Version, false)
		cancel()
		if err != nil {
			diagnostics.Printf(ctx, os.Stderr, "SCEP profile %s, payload %s: %v\n", profileID, row.Name, err)
		}
	}
}
