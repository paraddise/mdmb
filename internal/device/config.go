package device

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// defaultQueryResponses returns built-in answers to common
// DeviceInformation queries, layered with per-device values.
func defaultQueryResponses(d *Device) map[string]any {
	model := mapProductToModel(d.ProductName)
	responses := map[string]any{
		// per-device values
		"DeviceName":                 d.ComputerName,
		"SerialNumber":               d.Serial,
		"UDID":                       d.UDID,
		"OSVersion":                  d.OSVersion,
		"BuildVersion":               d.BuildVersion,
		"ProductName":                d.ProductName,
		"ModelName":                  model,
		"Model":                      d.ProductName,
		"MarketingName":              model,
		"TimeZone":                   "UTC",
		"TimeZoneOffsetFromUtc":      0,
		"AutoTimeZoneEnabled":        false,
		"MDMOptions":                 map[string]any{},
		"iTunesStoreAccountIsActive": false,
		"AwaitingConfiguration":      false,
		"ProductType":                d.ProductName,
		// realistic static defaults
		"ModelNumber":                "MX262LL/A",
		"DeviceCapacity":             256.0,
		"AvailableDeviceCapacity":    128.5,
		"BatteryLevel":               0.87,
		"IsSupervised":               true,
		"IsDeviceOwned":              true,
		"IsActivationLockEnabled":    true,
		"IsCloudBackupEnabled":       true,
		"PersonalHotspotEnabled":     false,
		"DeviceID":                   "",
		"EASDeviceIdentifier":        strings.ReplaceAll(d.UDID, "-", ""),
		"MEID":                       "",
		"IMEI":                       "",
		"ModemFirmwareVersion":       "3.02.02",
		"IsRoaming":                  false,
		"IsMultiUser":                false,
		"CurrentCarrierNetwork":      "Wi-Fi",
		"VoiceRoamingEnabled":        false,
		"DataRoamingEnabled":         false,
		"SIMCarrierPolicyIdentifier": "",
		"SubscriberCarrierNetwork":   "",
	}
	if d.ProductName == "Mac16,10" {
		responses["IsAppleSilicon"] = true
	}
	return responses
}

// mapProductToModel returns a human-readable marketing name for a
// product identifier. Falls back to the identifier itself.
func mapProductToModel(product string) string {
	switch product {
	case "":
		return "iPad Pro (11-inch) (4th generation)"
	case "Mac16,10":
		return "MacBook Pro (16-inch, Nov 2023)"
	default:
		// iPad identifiers get an iPad name; anything else echoes back.
		return product
	}
}

var queryTypes = func() map[string]string {
	types := map[string]string{}
	for kind, names := range map[string]string{
		"boolean": "IsCharging IsRoaming AutoTimeZoneEnabled IsSupervised IsMDMLostModeEnabled IsDeviceLocatorServiceEnabled IsDoNotDisturbInEffect IsNetworkTethered IsMultiUser AwaitingConfiguration iTunesStoreAccountIsActive IsAppleSilicon SupportsiOSAppInstalls BootstrapTokenAllowed HasBattery IsActivationLockSupported SystemIntegrityProtectionEnabled SupportsLOMDevice TemporarySessionOnly SkipLanguageAndLocaleSetupForNewUsers PINRequiredForEraseDevice PINRequiredForDeviceLock AppAnalyticsEnabled DiagnosticSubmissionEnabled IsDeviceOwned IsActivationLockEnabled IsCloudBackupEnabled PersonalHotspotEnabled VoiceRoamingEnabled DataRoamingEnabled",
		"integer": "CellularTechnology TimeZoneOffsetFromUtc MaximumResidentUsers EstimatedResidentUsers QuotaSize ResidentUsers UserSessionTimeout TemporarySessionTimeout OnlineAuthenticationGracePeriod",
		"real":    "DeviceCapacity AvailableDeviceCapacity BatteryLevel",
		"array":   "ActiveManagedUsers AutoSetupAdminAccounts ServiceSubscriptions ManagedAppleIDDefaultDomains EthernetMACs DevicePropertiesAttestation",
		"dict":    "MDMOptions OrganizationInfo OSUpdateSettings SoftwareUpdateSettings AccessibilitySettings",
		"date":    "LastCloudBackupDate",
		"data":    "PushToken",
		"string":  "UDID SerialNumber DeviceName Model ModelName OSVersion BuildVersion ProductName MarketingName WiFiMAC BluetoothMAC EthernetMAC SIMStatus CarrierSettingsVersion PhoneNumber SubscriberMCC SubscriberMNC CurrentMCC CurrentMNC ICCID EID IMEI MEID ModemFirmwareVersion TimeZone EnrollmentID AppleID iTunesStoreAccountHash DeviceID OrganizationName ManagedAppleID SupplementalBuildVersion SupplementalOSVersionExtra ProvisioningUDID shortName GUID SoftwareUpdateDeviceID SIMCarrierNetwork SIMMCC SIMMNC LocalHostName HostName EACSPreflight ModelNumber",
	} {
		for _, name := range strings.Fields(names) {
			types[name] = kind
		}
	}
	return types
}()

func queryValue(key string, value any) (any, error) {
	kind := queryTypes[key]
	legacy, isString := value.(string)
	if isString {
		switch kind {
		case "boolean":
			return strconv.ParseBool(legacy)
		case "integer":
			return strconv.ParseInt(legacy, 10, 64)
		case "real":
			number, err := strconv.ParseFloat(legacy, 64)
			if key == "BatteryLevel" && number > 1 {
				number /= 100
			}
			return validReal(key, number, err)
		case "date":
			return time.Parse(time.RFC3339, legacy)
		case "data":
			return base64.StdEncoding.DecodeString(legacy)
		case "array", "dict":
			if err := json.Unmarshal([]byte(legacy), &value); err != nil {
				return nil, err
			}
		}
	}
	switch kind {
	case "array":
		items, ok := value.([]any)
		if !ok {
			break
		}
		if key == "DevicePropertiesAttestation" {
			certificates := make([][]byte, 0, len(items))
			for _, item := range items {
				encoded, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("expected base64 certificate data")
				}
				data, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return nil, err
				}
				certificates = append(certificates, data)
			}
			return certificates, nil
		}
		return plistValue(items)
	case "dict":
		if object, ok := value.(map[string]any); ok {
			return plistValue(object)
		}
	case "boolean":
		if boolean, ok := value.(bool); ok {
			return boolean, nil
		}
	case "string":
		if isString {
			return legacy, nil
		}
	case "integer", "real":
		number, err := plistValue(value)
		if err != nil {
			return nil, err
		}
		switch n := number.(type) {
		case int64:
			if kind == "integer" {
				return n, nil
			}
			return validReal(key, float64(n), nil)
		case float64:
			if kind == "real" {
				return validReal(key, n, nil)
			}
			if math.Trunc(n) == n && n >= math.MinInt64 && n < math.MaxInt64 {
				return int64(n), nil
			}
		}
	case "":
		return plistValue(value)
	}
	return nil, fmt.Errorf("expected %s", kind)
}

func validReal(key string, number float64, err error) (any, error) {
	if err != nil || math.IsInf(number, 0) || math.IsNaN(number) || (key == "BatteryLevel" && (number < -1 || number > 1)) {
		return nil, fmt.Errorf("invalid numeric value")
	}
	return number, nil
}

func plistValue(value any) (any, error) {
	switch v := value.(type) {
	case nil:
		return nil, fmt.Errorf("null is not a property list value")
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n, nil
		}
		return v.Float64()
	case int:
		return int64(v), nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			parsed, err := plistValue(item)
			if err != nil {
				return nil, err
			}
			out[i] = parsed
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			parsed, err := plistValue(item)
			if err != nil {
				return nil, err
			}
			out[key] = parsed
		}
		return out, nil
	default:
		return v, nil
	}
}
