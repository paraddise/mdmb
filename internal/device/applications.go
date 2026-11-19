package device

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	plist "howett.net/plist"
)

const simulatorBucket = "device_simulator_state"

type ApplicationMetadata struct {
	Identifier   string
	Name         string
	Version      string
	ShortVersion string
	StoreID      uint64
	ManifestURL  string
}

type simulatedApp struct {
	ApplicationMetadata
	Managed         bool
	ManagementFlags uint64
	Configuration   map[string]any `plist:",omitempty"`
	Attributes      map[string]any `plist:",omitempty"`
}

type simulatorState struct {
	Applications map[string]simulatedApp
	Settings     map[string]any
}

func readSimulatorState(tx *bolt.Tx, udid string) (simulatorState, error) {
	state := simulatorState{}
	if raw := BucketGet(tx, simulatorBucket, udid); raw != nil {
		if _, err := plist.Unmarshal(raw, &state); err != nil {
			return state, err
		}
	}
	if state.Applications == nil {
		state.Applications = map[string]simulatedApp{}
	}
	if state.Settings == nil {
		state.Settings = map[string]any{}
	}
	return state, nil
}

func (d *Device) simulatorState() (state simulatorState, err error) {
	err = d.boltDB.View(func(tx *bolt.Tx) error {
		state, err = readSimulatorState(tx, d.UDID)
		return err
	})
	return
}

func (d *Device) updateSimulatorState(update func(*simulatorState) error) error {
	return d.boltDB.Update(func(tx *bolt.Tx) error {
		state, err := readSimulatorState(tx, d.UDID)
		if err != nil {
			return err
		}
		if err := update(&state); err != nil {
			return err
		}
		raw, err := plist.Marshal(state, plist.BinaryFormat)
		if err != nil {
			return err
		}
		return BucketPutOrDelete(tx, simulatorBucket, d.UDID, raw)
	})
}

func stringField(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func dictionaryField(values map[string]any, key string) map[string]any {
	value, _ := values[key].(map[string]any)
	return value
}

func boolField(values map[string]any, key string) bool {
	value, _ := values[key].(bool)
	return value
}

func unsignedField(value any) (uint64, bool) {
	switch n := value.(type) {
	case uint64:
		return n, true
	case int64:
		return uint64(n), n >= 0
	default:
		return 0, false
	}
}

// validateFields checks the outer shape of documented fields. A trailing !
// marks a required field, including data that must never be logged.
func validateFields(fields map[string]any, spec map[string]string) error {
	for key, kind := range spec {
		required := strings.HasSuffix(kind, "!")
		kind = strings.TrimSuffix(kind, "!")
		v, found := fields[key]
		if !found && !required {
			continue
		}
		var valid bool
		switch kind {
		case "string":
			text, ok := v.(string)
			valid = ok && (!required || strings.TrimSpace(text) != "")
		case "bool":
			_, valid = v.(bool)
		case "data":
			data, ok := v.([]byte)
			valid = ok && (!required || len(data) > 0)
		case "int":
			_, valid = unsignedField(v)
		case "dict":
			_, valid = v.(map[string]any)
		case "array", "strings":
			items, ok := v.([]any)
			valid = ok
			if kind == "strings" {
				for _, item := range items {
					if _, ok := item.(string); !ok {
						valid = false
					}
				}
			}
		}
		if !valid {
			return fmt.Errorf("%w: invalid or missing %s", errCommandFormat, key)
		}
	}
	return nil
}

func (d *Device) installApplication(reqType string, command map[string]any) (simulatedApp, error) {
	fields := map[string]string{"Identifier": "string", "iTunesStoreID": "int", "ManifestURL": "string",
		"Manifest": "dict", "InstallAsManaged": "bool", "ManagementFlags": "int",
		"Configuration": "dict", "Attributes": "dict", "ChangeManagementState": "string", "Options": "dict"}
	if err := validateFields(command, fields); err != nil {
		return simulatedApp{}, err
	}
	storeID, _ := unsignedField(command["iTunesStoreID"])
	manifestURL := stringField(command, "ManifestURL")
	if manifestURL != "" {
		parsed, err := url.Parse(manifestURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return simulatedApp{}, fmt.Errorf("%w: invalid ManifestURL", errCommandFormat)
		}
	}
	id := stringField(command, "Identifier")
	if id == "" && storeID == 0 && manifestURL == "" && command["Manifest"] == nil {
		return simulatedApp{}, fmt.Errorf("%w: missing application source", errCommandFormat)
	}
	meta := ApplicationMetadata{Identifier: id, StoreID: storeID, ManifestURL: manifestURL}
	if manifest := dictionaryField(command, "Manifest"); manifest != nil {
		items, _ := manifest["items"].([]any)
		for _, item := range items {
			entry, _ := item.(map[string]any)
			metadata := dictionaryField(entry, "metadata")
			if bundleID := stringField(metadata, "bundle-identifier"); bundleID != "" && (id == "" || id == bundleID) {
				meta.Identifier = bundleID
				meta.Name = stringField(metadata, "title")
				meta.Version = stringField(metadata, "bundle-version")
				break
			}
		}
	}
	for _, app := range d.inventoryOverrides.Applications {
		if (meta.Identifier != "" && app.Identifier == meta.Identifier) ||
			(meta.Identifier == "" && ((storeID != 0 && app.StoreID == storeID) || (manifestURL != "" && app.ManifestURL == manifestURL))) {
			if meta.Identifier == "" {
				meta.Identifier = app.Identifier
			}
			if meta.Name == "" {
				meta.Name = app.Name
			}
			if meta.Version == "" {
				meta.Version = app.Version
			}
			meta.ShortVersion = app.ShortVersion
			break
		}
	}
	if strings.TrimSpace(meta.Identifier) == "" {
		return simulatedApp{}, errors.New("application bundle identifier is unavailable")
	}

	var result simulatedApp
	err := d.updateSimulatorState(func(state *simulatorState) error {
		result = state.Applications[meta.Identifier]
		result.Identifier = meta.Identifier
		if meta.Name != "" || result.Name == "" {
			result.Name = meta.Name
			if result.Name == "" {
				result.Name = meta.Identifier
			}
		}
		if meta.Version != "" {
			result.Version = meta.Version
		}
		if meta.ShortVersion != "" {
			result.ShortVersion = meta.ShortVersion
		}
		if storeID != 0 {
			result.StoreID = storeID
		}
		// The remote manifest URL is only a catalog lookup key.
		result.Managed = reqType == "InstallApplication" || boolField(command, "InstallAsManaged")
		if flags, ok := unsignedField(command["ManagementFlags"]); ok {
			result.ManagementFlags = flags
		}
		if config := dictionaryField(command, "Configuration"); config != nil {
			result.Configuration = config
		}
		if attrs := dictionaryField(command, "Attributes"); attrs != nil {
			result.Attributes = attrs
		}
		state.Applications[result.Identifier] = result
		return nil
	})
	return result, err
}

func (d *Device) applicationInventory(reqType string, command map[string]any) (map[string]any, error) {
	if err := validateFields(command, map[string]string{"Identifiers": "strings", "ManagedAppsOnly": "bool", "Items": "strings"}); err != nil {
		return nil, err
	}
	if (reqType == "ManagedApplicationConfiguration" || reqType == "ManagedApplicationAttributes") && command["Identifiers"] == nil {
		return nil, fmt.Errorf("%w: missing Identifiers", errCommandFormat)
	}
	state, err := d.simulatorState()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(state.Applications))
	for id := range state.Applications {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	installed := make([]map[string]any, 0)
	attributes := make([]map[string]any, 0)
	configurations := make([]map[string]any, 0)
	managed := map[string]any{}
	for _, id := range ids {
		app := state.Applications[id]
		if (reqType != "InstalledApplicationList" || boolField(command, "ManagedAppsOnly")) && !app.Managed {
			continue
		}
		if filter, ok := command["Identifiers"].([]any); ok && len(filter) > 0 && !containsString(filter, id) {
			continue
		}
		switch reqType {
		case "InstalledApplicationList":
			record := map[string]any{"Identifier": id, "Name": app.Name, "Version": app.Version,
				"ShortVersion": app.ShortVersion, "AppStoreVendable": app.StoreID != 0, "Installing": false}
			if items, ok := command["Items"].([]any); ok && len(items) > 0 {
				for key := range record {
					if key != "Identifier" && !containsString(items, key) {
						delete(record, key)
					}
				}
			}
			installed = append(installed, record)
		case "ManagedApplicationList":
			managed[id] = map[string]any{"Status": "Managed", "ManagementFlags": app.ManagementFlags, "HasConfiguration": app.Configuration != nil}
		case "ManagedApplicationConfiguration":
			record := map[string]any{"Identifier": id}
			if app.Configuration != nil {
				record["Configuration"] = app.Configuration
			}
			configurations = append(configurations, record)
		case "ManagedApplicationAttributes":
			record := map[string]any{"Identifier": id}
			if app.Attributes != nil {
				record["Attributes"] = app.Attributes
			}
			attributes = append(attributes, record)
		}
	}
	switch reqType {
	case "InstalledApplicationList":
		return map[string]any{"InstalledApplicationList": installed}, nil
	case "ManagedApplicationList":
		return map[string]any{"ManagedApplicationList": managed}, nil
	case "ManagedApplicationConfiguration":
		return map[string]any{"ApplicationConfigurations": configurations}, nil
	default:
		return map[string]any{"ApplicationAttributes": attributes}, nil
	}
}

func containsString(items []any, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func (d *Device) applySettings(command map[string]any) ([]map[string]any, error) {
	if err := validateFields(command, map[string]string{"Settings": "array!"}); err != nil {
		return nil, err
	}
	settings := command["Settings"].([]any)
	results := make([]map[string]any, 0, len(settings))
	err := d.updateSimulatorState(func(state *simulatorState) error {
		for _, entry := range settings {
			item, _ := entry.(map[string]any)
			name := stringField(item, "Item")
			id := stringField(item, "Identifier")
			result := map[string]any{"Item": name, "Status": "Acknowledged"}
			if id != "" {
				result["Identifier"] = id
			}
			if err := applySetting(state, name, item); err != nil {
				result["Status"] = "Error"
				result["ErrorChain"] = []ErrorChain{{ErrorCode: 12021, ErrorDomain: "MCMDMErrorDomain", LocalizedDescription: err.Error()}}
			}
			results = append(results, result)
		}
		return nil
	})
	return results, err
}

func applySetting(state *simulatorState, name string, item map[string]any) error {
	switch name {
	case "ApplicationConfiguration", "ApplicationAttributes":
		field := strings.TrimPrefix(name, "Application")
		if err := validateFields(item, map[string]string{"Identifier": "string!", field: "dict"}); err != nil {
			return err
		}
		id := stringField(item, "Identifier")
		app, found := state.Applications[id]
		if !found || !app.Managed {
			return errors.New("managed application is unavailable")
		}
		if field == "Configuration" {
			app.Configuration = dictionaryField(item, field)
		} else {
			app.Attributes = dictionaryField(item, field)
		}
		state.Applications[id] = app
	case "TimeZone":
		if err := validateFields(item, map[string]string{"TimeZone": "string!"}); err != nil {
			return err
		}
		name := stringField(item, "TimeZone")
		if _, err := time.LoadLocation(name); err != nil || name == "Local" {
			return errors.New("invalid time zone")
		}
		state.Settings["TimeZone"] = name
		state.Settings["AutoTimeZoneEnabled"] = false
	case "MDMOptions":
		if err := validateFields(item, map[string]string{"MDMOptions": "dict!"}); err != nil {
			return err
		}
		if err := validateFields(dictionaryField(item, "MDMOptions"), map[string]string{"BootstrapTokenAllowed": "bool",
			"ActivationLockAllowedWhileSupervised": "bool", "PromptUserToAllowBootstrapTokenForAuthentication": "bool", "IdleRebootAllowed": "bool"}); err != nil {
			return err
		}
		state.Settings["MDMOptions"] = dictionaryField(item, "MDMOptions")
	case "Wallpaper":
		if err := validateFields(item, map[string]string{"Image": "data!", "Where": "int!"}); err != nil {
			return err
		}
		if _, format, err := image.DecodeConfig(bytes.NewReader(item["Image"].([]byte))); err != nil || (format != "png" && format != "jpeg") {
			return errors.New("wallpaper must be PNG or JPEG")
		}
		where, _ := unsignedField(item["Where"])
		if where < 1 || where > 3 {
			return errors.New("invalid wallpaper destination " + strconv.FormatUint(where, 10))
		}
	default:
		return errors.New("unsupported setting")
	}
	return nil
}
