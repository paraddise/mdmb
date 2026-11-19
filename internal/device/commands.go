package device

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jessepeterson/mdmb/internal/diagnostics"
)

var errCommandFormat = errors.New("invalid command format")

func (c *MDMClient) handleMDMEnvelope(ctx context.Context, reqType, commandUUID string, command map[string]any) any {
	envelope := ConnectRequest{UDID: c.Device.UDID, CommandUUID: commandUUID, Status: "Acknowledged"}
	if c.notNow {
		envelope.Status = "NotNow"
		return &envelope
	}
	var err error
	var result any
	if command == nil || reqType == "" {
		err = errCommandFormat
	} else if err = validateFields(command, map[string]string{"RequestRequiresNetworkTether": "bool"}); err == nil {
		result, err = c.dispatchCommand(ctx, reqType, envelope, command)
	}
	if err == nil {
		return result
	}
	envelope.Status = "Error"
	if errors.Is(err, errCommandFormat) {
		envelope.Status = "CommandFormatError"
	}
	diagnostics.Printf(ctx, os.Stdout, "MDM %q UUID %q: %v\n", reqType, commandUUID, err)
	envelope.ErrorChain = []ErrorChain{{
		ErrorCode: 12021, ErrorDomain: "MCMDMErrorDomain", LocalizedDescription: err.Error(),
	}}
	return &envelope
}

func (c *MDMClient) dispatchCommand(ctx context.Context, reqType string, envelope ConnectRequest, command map[string]any) (any, error) {
	d := c.Device
	response := map[string]any{"UDID": envelope.UDID, "CommandUUID": envelope.CommandUUID, "Status": envelope.Status}
	switch reqType {
	case "DeviceInformation":
		return c.handleDeviceInfo(ctx, envelope, command)
	case "SecurityInfo":
		return &SecurityInfoResponse{ConnectRequest: envelope, SecurityInfo: d.EffectiveSecurityInfo()}, nil
	case "ProfileList", "CertificateList":
		if err := validateFields(command, map[string]string{"ManagedOnly": "bool"}); err != nil {
			return nil, err
		}
		managed := boolField(command, "ManagedOnly")
		var err error
		if reqType == "ProfileList" {
			response[reqType], err = d.profileInventory(managed)
		} else {
			response[reqType], err = d.certificateInventory(managed)
		}
		return response, err
	case "InstallProfile":
		if err := validateFields(command, map[string]string{"Payload": "data!"}); err != nil {
			return nil, err
		}
		id, err := d.installProfileFromMDM(ctx, command["Payload"].([]byte))
		return &InstallProfileResponse{ConnectRequest: envelope, profileID: id}, err
	case "RemoveProfile":
		if err := validateFields(command, map[string]string{"Identifier": "string!"}); err != nil {
			return nil, err
		}
		id := stringField(command, "Identifier")
		if id == d.MDMProfileIdentifier {
			return nil, errors.New("active enrollment profile cannot be removed")
		}
		return response, d.SystemProfileStore().removeProfile(id)
	case "InstallApplication", "InstallEnterpriseApplication":
		app, err := d.installApplication(reqType, command)
		if err == nil && reqType == "InstallApplication" {
			response["Identifier"], response["State"] = app.Identifier, "Managed"
		}
		return response, err
	case "RemoveApplication":
		if err := validateFields(command, map[string]string{"Identifier": "string!"}); err != nil {
			return nil, err
		}
		return response, d.updateSimulatorState(func(state *simulatorState) error {
			delete(state.Applications, stringField(command, "Identifier"))
			return nil
		})
	case "InstalledApplicationList", "ManagedApplicationList", "ManagedApplicationConfiguration", "ManagedApplicationAttributes":
		fields, err := d.applicationInventory(reqType, command)
		for key, value := range fields {
			response[key] = value
		}
		return response, err
	case "Settings":
		var err error
		response["Settings"], err = d.applySettings(command)
		return response, err
	case "DeclarativeManagement":
		token, err := declarativeCommandToken(command)
		return &declarativeManagementResponse{ConnectRequest: envelope, token: token}, err
	default:
		if err := validateSimulatedAction(reqType, command); err != nil {
			return nil, err
		}
		diagnostics.Printf(ctx, os.Stdout, "MDM simulated %s for %q, command %q\n", reqType, d.UDID, envelope.CommandUUID)
		return response, nil
	}
}

func validateSimulatedAction(reqType string, command map[string]any) error {
	var fields map[string]string
	switch reqType {
	case "RestartDevice":
		fields = map[string]string{"NotifyUser": "bool", "RebuildKernelCache": "bool", "KextPaths": "strings"}
	case "ShutDownDevice", "StopMirroring":
	case "EraseDevice":
		fields = map[string]string{"PIN": "string", "PreserveDataPlan": "bool", "DisallowProximitySetup": "bool",
			"ObliterationBehavior": "string", "ReturnToService": "dict"}
	case "DeviceLock":
		fields = map[string]string{"PIN": "string", "Message": "string", "PhoneNumber": "string"}
	case "ClearPasscode":
		fields = map[string]string{"UnlockToken": "data!"}
	case "SetRecoveryLock":
		fields = map[string]string{"NewPassword": "string", "CurrentPassword": "string"}
		// An empty new password disables Recovery Lock.
		if _, ok := command["NewPassword"]; !ok {
			return fmt.Errorf("%w: missing NewPassword", errCommandFormat)
		}
	case "AccountConfiguration":
		fields = map[string]string{"SkipPrimarySetupAccountCreation": "bool", "SetPrimarySetupAccountAsRegularUser": "bool",
			"PrimaryAccountFullName": "string", "PrimaryAccountUserName": "string",
			"DontAutoPopulatePrimaryAccountInfo": "bool", "LockPrimaryAccountInfo": "bool",
			"AutoSetupAdminAccounts": "array", "ManagedLocalUserShortName": "string"}
		if accounts, ok := command["AutoSetupAdminAccounts"].([]any); ok {
			for _, entry := range accounts {
				account, _ := entry.(map[string]any)
				if err := validateFields(account, map[string]string{"shortName": "string!", "fullName": "string!", "passwordHash": "data!"}); err != nil {
					return err
				}
			}
		}
	case "DeleteUser":
		fields = map[string]string{"UserName": "string", "ForceDeletion": "bool", "DeleteAllUsers": "bool"}
		if stringField(command, "UserName") == "" && !boolField(command, "DeleteAllUsers") {
			return fmt.Errorf("%w: missing UserName or DeleteAllUsers", errCommandFormat)
		}
	case "SetAutoAdminPassword":
		fields = map[string]string{"GUID": "string!", "passwordHash": "data!"}
	case "InstallMedia":
		fields = map[string]string{"MediaType": "string!", "iTunesStoreID": "int", "MediaURL": "string",
			"PersistentID": "string", "Kind": "string", "Version": "string", "Author": "string", "Title": "string"}
		id, _ := unsignedField(command["iTunesStoreID"])
		if id == 0 && stringField(command, "MediaURL") == "" {
			return fmt.Errorf("%w: missing media source", errCommandFormat)
		}
	case "RequestMirroring":
		fields = map[string]string{"DestinationName": "string", "DestinationDeviceID": "string", "Password": "string", "ScanTime": "int"}
		if stringField(command, "DestinationName") == "" && stringField(command, "DestinationDeviceID") == "" {
			return fmt.Errorf("%w: missing mirroring destination", errCommandFormat)
		}
	default:
		return fmt.Errorf("unknown command %q", reqType)
	}
	return validateFields(command, fields)
}

type DeviceInfoCommand struct {
	ConnectResponseCommand
	Queries []string
}

type DeviceInfo struct {
	Command     DeviceInfoCommand
	CommandUUID string
}

type DeviceInfoResponse struct {
	ConnectRequest
	QueryResponses map[string]any
}

func (c *MDMClient) handleDeviceInfo(ctx context.Context, envelope ConnectRequest, command map[string]any) (any, error) {
	if err := validateFields(command, map[string]string{"Queries": "strings!", "DeviceAttestationNonce": "data"}); err != nil {
		return nil, err
	}
	resp := &DeviceInfoResponse{ConnectRequest: envelope, QueryResponses: map[string]any{}}
	responses := c.Device.QueryResponses()
	var unavailable []string
	for _, item := range command["Queries"].([]any) {
		key := item.(string)
		if val, ok := responses[key]; ok {
			resp.QueryResponses[key] = val
		} else {
			unavailable = append(unavailable, key)
		}
	}
	if len(unavailable) > 0 {
		diagnostics.Printf(ctx, os.Stdout, "unavailable DeviceInformation queries: %q\n", strings.Join(unavailable, ", "))
	}
	return resp, nil
}

type InstallProfileResponse struct {
	ConnectRequest
	profileID string
}
