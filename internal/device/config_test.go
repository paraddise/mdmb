package device

import (
	"testing"

	howettPlist "howett.net/plist"
)

// binaryDeviceInfoPlist builds a DeviceInformation command as a
// binary (bplist00) plist, the format some MDM servers reply with.
func binaryDeviceInfoPlist(t *testing.T) []byte {
	t.Helper()
	cmd := map[string]interface{}{
		"Command": map[string]interface{}{
			"RequestType": "DeviceInformation",
			"Queries":     []string{"DeviceName", "SerialNumber", "UDID", "OSVersion", "ModelName"},
		},
		"CommandUUID": "test-uuid",
	}
	b, err := howettPlist.Marshal(cmd, howettPlist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnmarshalPlistBinary(t *testing.T) {
	b := binaryDeviceInfoPlist(t)
	if string(b[:6]) != "bplist" {
		t.Fatalf("expected binary plist, got %q", b[:6])
	}
	cmd := &DeviceInfo{}
	if err := unmarshalPlist(b, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.CommandUUID != "test-uuid" || cmd.Command.RequestType != "DeviceInformation" {
		t.Fatalf("unexpected decode: %+v", cmd)
	}
}

func TestUnmarshalPlistXML(t *testing.T) {
	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CommandUUID</key><string>x</string></dict></plist>`)
	cmd := &DeviceInfo{}
	if err := unmarshalPlist(xml, cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.CommandUUID != "x" {
		t.Fatalf("unexpected decode: %+v", cmd)
	}
}

func TestUnmarshalPlistGarbage(t *testing.T) {
	if err := unmarshalPlist([]byte("<html>Not Found</html>"), &DeviceInfo{}); err == nil {
		t.Fatal("expected error for non-plist payload")
	}
}

func TestHandleDeviceInfoBinaryPlist(t *testing.T) {
	d := New("Test iPad", nil)
	c := &MDMClient{Device: d}
	resp := dispatchTestCommand(t, c, binaryDeviceInfoPlist(t)).(*DeviceInfoResponse)
	if resp.Status != "Acknowledged" {
		t.Fatalf("expected Acknowledged, got %s", resp.Status)
	}
	for _, q := range []string{"DeviceName", "SerialNumber", "UDID", "OSVersion", "ModelName"} {
		if _, ok := resp.QueryResponses[q]; !ok {
			t.Errorf("missing query response for %s", q)
		}
	}
	if resp.QueryResponses["DeviceName"] != "Test iPad" {
		t.Errorf("wrong DeviceName: %s", resp.QueryResponses["DeviceName"])
	}
}

func TestHandleSecurityInfo(t *testing.T) {
	d := New("", nil)
	c := &MDMClient{Device: d}
	raw, err := howettPlist.Marshal(map[string]any{"Command": map[string]any{"RequestType": "SecurityInfo"}, "CommandUUID": "u"}, howettPlist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	resp := dispatchTestCommand(t, c, raw).(*SecurityInfoResponse)
	if resp.SecurityInfo["PasscodeCompliant"] != true {
		t.Error("expected PasscodeCompliant default true")
	}
}
