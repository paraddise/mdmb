package device

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

const inventoryBucket = "device_inventory_overrides"

type SecurityOverrides struct {
	FDE_Enabled                            *bool `json:",omitempty"`
	SystemIntegrityProtectionEnabled       *bool `json:",omitempty"`
	FirewallEnabled                        *bool `json:",omitempty"`
	AutoLockTime                           *int  `json:",omitempty"`
	IsRecoveryLockEnabled                  *bool `json:",omitempty"`
	RemoteDesktopEnabled                   *bool `json:",omitempty"`
	PasscodeLockGracePeriodEnforced        *int  `json:",omitempty"`
	PasscodePresent                        *bool `json:",omitempty"`
	PasscodeCompliant                      *bool `json:",omitempty"`
	PasscodeCompliantWithProfiles          *bool `json:",omitempty"`
	PasscodeLockGracePeriod                *int  `json:",omitempty"`
	PasscodeMaxGracePeriod                 *int  `json:",omitempty"`
	HardwareEncryption                     *int  `json:",omitempty"`
	ActivationLockEnabled                  *bool `json:",omitempty"`
	BootstrapTokenAllowedForAuthentication *bool `json:",omitempty"`
}

type InventoryOverrides struct {
	QueryResponses map[string]any
	Applications   []ApplicationMetadata
	SecurityInfo   SecurityOverrides
}

type Inventory struct {
	ComputerName string
	Serial       string
	ProductName  string
	OSVersion    string
	BuildVersion string
	InventoryOverrides
}

func (d *Device) Inventory() Inventory {
	return Inventory{
		ComputerName:       d.ComputerName,
		Serial:             d.Serial,
		ProductName:        d.ProductName,
		OSVersion:          d.OSVersion,
		BuildVersion:       d.BuildVersion,
		InventoryOverrides: d.inventoryOverrides,
	}
}

func (d *Device) loadInventoryOverrides(tx *bolt.Tx) error {
	raw := BucketGet(tx, inventoryBucket, d.UDID)
	if len(raw) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&d.inventoryOverrides); err != nil {
		return fmt.Errorf("loading inventory for %s: %w", d.UDID, err)
	}
	return nil
}

func (d *Device) UpdateInventory(inventory Inventory) error {
	if strings.TrimSpace(inventory.Serial) == "" {
		return errors.New("Serial is required")
	}
	for key := range inventory.QueryResponses {
		if _, err := queryValue(key, inventory.QueryResponses[key]); err != nil {
			return fmt.Errorf("QueryResponses.%s: %w", key, err)
		}
		if strings.TrimSpace(key) == "" {
			return errors.New("QueryResponses keys must be nonempty")
		}
	}
	identifiers := map[string]bool{}
	storeIDs := map[uint64]bool{}
	manifestURLs := map[string]bool{}
	for _, app := range inventory.Applications {
		if strings.TrimSpace(app.Identifier) == "" || identifiers[app.Identifier] ||
			(app.StoreID != 0 && storeIDs[app.StoreID]) || (app.ManifestURL != "" && manifestURLs[app.ManifestURL]) {
			return errors.New("Applications must have unique bundle identifiers, store IDs and manifest URLs")
		}
		identifiers[app.Identifier] = true
		storeIDs[app.StoreID] = true
		manifestURLs[app.ManifestURL] = true
	}
	var raw []byte
	if len(inventory.QueryResponses) != 0 || len(inventory.Applications) != 0 || inventory.SecurityInfo != (SecurityOverrides{}) {
		var err error
		raw, err = json.Marshal(inventory.InventoryOverrides)
		if err != nil {
			return err
		}
	}
	err := d.boltDB.Update(func(tx *bolt.Tx) error {
		if BucketGetString(tx, "device_serial", d.UDID) == "" {
			return errors.New("device not found")
		}
		if err := putInventoryFields(tx, d.UDID, inventory); err != nil {
			return err
		}
		return BucketPutOrDelete(tx, inventoryBucket, d.UDID, raw)
	})
	if err == nil {
		d.ComputerName = inventory.ComputerName
		d.Serial = inventory.Serial
		d.ProductName = inventory.ProductName
		d.OSVersion = inventory.OSVersion
		d.BuildVersion = inventory.BuildVersion
		d.inventoryOverrides = inventory.InventoryOverrides
	}
	return err
}

func putInventoryFields(tx *bolt.Tx, udid string, inventory Inventory) error {
	fields := [...]struct{ bucket, value string }{
		{"device_serial", inventory.Serial},
		{"device_computer_name", inventory.ComputerName},
		{"device_product_name", inventory.ProductName},
		{"device_os_version", inventory.OSVersion},
		{"device_build_version", inventory.BuildVersion},
	}
	for _, field := range fields {
		if err := BucketPutOrDeleteString(tx, field.bucket, udid, field.value); err != nil {
			return err
		}
	}
	return nil
}

func (d *Device) QueryResponses() map[string]any {
	responses := defaultQueryResponses(d)
	responses["IsActivationLockEnabled"] = valueOrDefault(d.inventoryOverrides.SecurityInfo.ActivationLockEnabled, true)
	for key, value := range d.inventoryOverrides.QueryResponses {
		if converted, err := queryValue(key, value); err == nil {
			responses[key] = converted
		}
	}
	if d.boltDB != nil {
		if state, err := d.simulatorState(); err == nil {
			for key, value := range state.Settings {
				responses[key] = value
			}
			if zone, ok := state.Settings["TimeZone"].(string); ok {
				if location, err := time.LoadLocation(zone); err == nil {
					_, offset := time.Now().In(location).Zone()
					responses["TimeZoneOffsetFromUtc"] = offset
				}
			}
		}
	}
	return responses
}

// SecurityInfoResponse is the response to the MDM SecurityInfo command.
type SecurityInfoResponse struct {
	ConnectRequest
	SecurityInfo map[string]any
}

func (d *Device) EffectiveSecurityInfo() map[string]any {
	custom := d.inventoryOverrides.SecurityInfo
	result := map[string]any{
		"PasscodePresent":                 valueOrDefault(custom.PasscodePresent, true),
		"PasscodeCompliant":               valueOrDefault(custom.PasscodeCompliant, true),
		"PasscodeCompliantWithProfiles":   valueOrDefault(custom.PasscodeCompliantWithProfiles, true),
		"PasscodeLockGracePeriodEnforced": valueOrDefault(custom.PasscodeLockGracePeriodEnforced, valueOrDefault(custom.PasscodeMaxGracePeriod, 2)),
		"HardwareEncryptionCaps":          valueOrDefault(custom.HardwareEncryption, 2),
	}
	result["FDE_Enabled"] = valueOrDefault(custom.FDE_Enabled, false)
	result["SystemIntegrityProtectionEnabled"] = valueOrDefault(custom.SystemIntegrityProtectionEnabled, true)
	result["FirewallSettings"] = map[string]any{"FirewallEnabled": valueOrDefault(custom.FirewallEnabled, false)}
	bootstrap := "not supported"
	if d.ProductName == "Mac16,10" || custom.BootstrapTokenAllowedForAuthentication != nil {
		bootstrap = "disallowed"
		if valueOrDefault(custom.BootstrapTokenAllowedForAuthentication, true) {
			bootstrap = "allowed"
		}
	}
	result["BootstrapTokenAllowedForAuthentication"] = bootstrap
	if custom.AutoLockTime != nil {
		result["AutoLockTime"] = *custom.AutoLockTime
	}
	if custom.IsRecoveryLockEnabled != nil {
		result["IsRecoveryLockEnabled"] = *custom.IsRecoveryLockEnabled
	}
	if custom.RemoteDesktopEnabled != nil {
		result["RemoteDesktopEnabled"] = *custom.RemoteDesktopEnabled
	}
	if custom.PasscodeLockGracePeriod != nil {
		result["PasscodeLockGracePeriod"] = *custom.PasscodeLockGracePeriod
	}
	return result
}

func valueOrDefault[T any](override *T, fallback T) T {
	if override != nil {
		return *override
	}
	return fallback
}
