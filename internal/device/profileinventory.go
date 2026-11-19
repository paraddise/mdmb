package device

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

type inventoryProfile struct {
	id      string
	raw     []byte
	managed bool
}

func (d *Device) inventoryProfiles() (profiles []inventoryProfile, err error) {
	prefix := d.UDID + "_"
	err = d.boltDB.View(func(tx *bolt.Tx) error {
		for _, key := range BucketGetKeysWithPrefix(tx, "profiles", prefix, false) {
			profiles = append(profiles, inventoryProfile{id: key[len(prefix):],
				raw:     bytes.Clone(BucketGet(tx, "profiles", key)),
				managed: BucketGetString(tx, managedProfileBucket, key) == "1"})
		}
		return nil
	})
	return
}

func (d *Device) profileInventory(managedOnly bool) ([]map[string]any, error) {
	profiles, err := d.inventoryProfiles()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(profiles))
	for _, profile := range profiles {
		if managedOnly && !profile.managed {
			continue
		}
		var envelope map[string]any
		if err := unmarshalPlist(profile.raw, &envelope); err != nil {
			return nil, fmt.Errorf("reading stored profile metadata: %w", err)
		}
		record := map[string]any{"PayloadIdentifier": profile.id, "IsManaged": profile.managed,
			"IsEncrypted": envelope["EncryptedPayloadContent"] != nil}
		copyProfileMetadata(record, envelope)
		content := make([]map[string]any, 0)
		decoded, _, err := d.decodedProfile(profile.raw)
		if err == nil {
			payloads, _ := decoded["PayloadContent"].([]any)
			for _, item := range payloads {
				payload, _ := item.(map[string]any)
				if kind := stringField(payload, "PayloadType"); kind != "" {
					metadata := map[string]any{"PayloadType": kind}
					copyProfileMetadata(metadata, payload)
					content = append(content, metadata)
				}
			}
		}
		record["PayloadContent"] = content
		result = append(result, record)
	}
	return result, nil
}

func copyProfileMetadata(destination, source map[string]any) {
	for _, key := range []string{"PayloadIdentifier", "PayloadUUID", "PayloadVersion", "PayloadDisplayName",
		"PayloadOrganization", "PayloadDescription", "PayloadRemovalDisallowed"} {
		if value, ok := source[key]; ok {
			destination[key] = value
		}
	}
}

const managedCertificateBucket = "device_managed_certificates"

type certificateInventoryItem struct {
	CommonName string
	IsIdentity bool
	Data       []byte
}

func (d *Device) certificateInventory(managedOnly bool) ([]certificateInventoryItem, error) {
	certificates, err := d.Certificates()
	if err != nil {
		return nil, err
	}
	profiles, err := d.inventoryProfiles()
	if err != nil {
		return nil, err
	}
	managedSCEP := map[string]bool{}
	result := make([]certificateInventoryItem, 0)
	indices := map[string]int{}
	add := func(cert *x509.Certificate, identity, managed bool) {
		if managedOnly && !managed {
			return
		}
		key := string(cert.Raw)
		if index, ok := indices[key]; ok {
			result[index].IsIdentity = result[index].IsIdentity || identity
		} else {
			indices[key] = len(result)
			result = append(result, certificateInventoryItem{CommonName: cert.Subject.CommonName, IsIdentity: identity, Data: cert.Raw})
		}
	}
	for _, profile := range profiles {
		managed := profile.managed || profile.id == d.MDMProfileIdentifier
		if managedOnly && !managed {
			continue
		}
		if managed {
			// Recognize identities issued before managed provenance was stored.
			if payloads, err := d.SCEPPayloads(profile.id); err == nil {
				for _, payload := range payloads {
					if id := payload.Status.CertificateUUID; id != "" {
						managedSCEP[id] = true
					}
				}
			}
		}
		decoded, _, err := d.decodedProfile(profile.raw)
		if err != nil {
			continue
		}
		payloads, _ := decoded["PayloadContent"].([]any)
		for _, item := range payloads {
			payload, _ := item.(map[string]any)
			switch stringField(payload, "PayloadType") {
			case "com.apple.security.root", "com.apple.security.pkcs1", "com.apple.security.pem":
				raw, _ := payload["PayloadContent"].([]byte)
				addProfileCertificates(raw, func(cert *x509.Certificate) { add(cert, false, managed) })
			}
		}
	}
	for _, cert := range certificates {
		add(cert.X509, cert.IsIdentity, cert.Managed || cert.MDMIdentity || managedSCEP[cert.UUID])
	}
	// A public duplicate can be managed even if the identity link comes from an unmanaged source.
	for _, cert := range certificates {
		if index, ok := indices[string(cert.X509.Raw)]; ok && cert.IsIdentity {
			result[index].IsIdentity = true
		}
	}
	return result, nil
}

func addProfileCertificates(raw []byte, add func(*x509.Certificate)) {
	if certs, err := x509.ParseCertificates(raw); err == nil {
		for _, cert := range certs {
			add(cert)
		}
		return
	}
	for len(raw) != 0 {
		block, next := pem.Decode(raw)
		if block == nil {
			return
		}
		raw = next
		if block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				add(cert)
			}
		}
	}
}
