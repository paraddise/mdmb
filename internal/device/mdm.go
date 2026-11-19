package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/groob/plist"

	"github.com/jessepeterson/mdmb/internal/diagnostics"
)

func (c *MDMClient) authenticate(ctx context.Context) error {
	ar := &AuthenticationRequest{
		DeviceName:  c.Device.ComputerName,
		MessageType: "Authenticate",
		Topic:       c.MDMPayload.Topic,
		UDID:        c.Device.UDID,

		// non-required fields
		SerialNumber: c.Device.Serial,
		BuildVersion: c.Device.BuildVersion,
		OSVersion:    c.Device.OSVersion,
		ProductName:  c.Device.ProductName,
	}

	return c.checkinRequest(ctx, ar)
}

// AuthenticationRequest ...
type AuthenticationRequest struct {
	BuildVersion string `plist:",omitempty"`
	DeviceName   string
	IMEI         string `plist:",omitempty"`
	MEID         string `plist:",omitempty"`
	MessageType  string
	Model        string `plist:",omitempty"`
	ModelName    string `plist:",omitempty"`
	OSVersion    string `plist:",omitempty"`
	ProductName  string `plist:",omitempty"`
	SerialNumber string `plist:",omitempty"`
	Topic        string
	UDID         string
	EnrollmentID string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
}

type ErrorChain struct {
	ErrorCode            int
	ErrorDomain          string
	LocalizedDescription string
	USEnglishDescription string `plist:",omitempty"`
}

type ConnectRequest struct {
	UDID        string
	CommandUUID string `plist:",omitempty"`
	Status      string
	ErrorChain  []ErrorChain `plist:",omitempty"`

	RequestType string `plist:",omitempty"`
}

func (c *MDMClient) MdmSignature(ctx context.Context, body []byte) (string, error) {
	return c.transport.SignMessage(ctx, body)
}

type TokenUpdateRequest struct {
	AwaitingConfiguration bool   `plist:",omitempty"`
	EnrollmentID          string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
	EnrollmentUserID      string `plist:",omitempty"` // macOS 10.15 and iOS 13.0 and later
	MessageType           string
	NotOnConsole          bool `plist:",omitempty"`
	PushMagic             string
	Token                 []byte
	Topic                 string
	UDID                  string
	UnlockToken           []byte `plist:",omitempty"`
	UserShortName         string `plist:",omitempty"`
	UserID                string `plist:",omitempty"`
	UserLongName          string `plist:",omitempty"`
}

// PlistReader encodes i into XML Plist and returns a reader.
func PlistReader(i interface{}) (io.Reader, error) {
	buf := new(bytes.Buffer)
	enc := plist.NewEncoder(buf)
	enc.Indent("\t")
	err := enc.Encode(i)
	return buf, err
}

func (c *MDMClient) checkinRequest(ctx context.Context, i interface{}) error {
	r, err := PlistReader(i)
	if err != nil {
		return err
	}

	resp, err := c.transport.DoCheckIn(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("checkin request failed with HTTP status: %s", resp.Status)
	}

	return nil
}

func (c *MDMClient) TokenUpdate(ctx context.Context, addl string) error {
	tu := &TokenUpdateRequest{
		MessageType: "TokenUpdate",
		PushMagic:   "fakePushMagic" + addl,
		Token:       []byte("fakeToken" + addl),
		Topic:       c.MDMPayload.Topic,
		UDID:        c.Device.UDID,
	}
	return c.checkinRequest(ctx, tu)
}

type ConnectResponseCommand struct {
	RequestType string
}

func (c *MDMClient) Connect(ctx context.Context) error {
	req := &ConnectRequest{
		UDID:   c.Device.UDID,
		Status: "Idle",
	}
	auto, err := c.Device.AutoSCEPEnroll()
	if err != nil {
		diagnostics.Printf(ctx, os.Stderr, "SCEP settings: %v\n", err)
	}
	err = c.connect(ctx, req, auto)
	if auto && ctx.Err() == nil {
		ids, listErr := c.Device.SystemProfileStore().ListUUIDs()
		if listErr != nil {
			diagnostics.Printf(ctx, os.Stderr, "SCEP profiles: %v\n", listErr)
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				break
			}
			c.Device.autoEnrollProfile(ctx, id)
		}
	}
	return err
}

func (c *MDMClient) connect(ctx context.Context, connReq any, auto bool) error {
	if !c.enrolled() {
		return errors.New("device not enrolled")
	}
	for {
		r, err := PlistReader(connReq)
		if err != nil {
			return err
		}
		res, err := c.transport.DoReportResultsAndFetchNextCommand(ctx, r)
		if err != nil {
			return err
		}
		respBytes, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return err
		}
		if res.StatusCode != 200 {
			return fmt.Errorf("connect request failed with HTTP status: %s", res.Status)
		}

		// Post-acknowledgment work runs only once the server accepts the result.
		switch response := connReq.(type) {
		case *InstallProfileResponse:
			if auto {
				c.Device.autoEnrollProfile(ctx, response.profileID)
			}
		case *declarativeManagementResponse:
			c.afterDeclarativeAcknowledgment(ctx, response.token)
		}
		if len(respBytes) == 0 {
			return nil
		}

		var envelope map[string]any
		if err := unmarshalPlist(respBytes, &envelope); err != nil {
			return err
		}
		commandUUID := stringField(envelope, "CommandUUID")
		if commandUUID == "" {
			return errors.New("MDM command has no CommandUUID")
		}
		reqType := stringField(dictionaryField(envelope, "Command"), "RequestType")
		connReq = c.handleMDMEnvelope(ctx, reqType, commandUUID, dictionaryField(envelope, "Command"))
	}
}
