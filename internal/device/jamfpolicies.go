package device

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

const (
	jamfPolicyBucket      = "device_jamf_policies"
	jamfNamespace         = "http://www.jamfsoftware.com/JAMFMessage"
	jamfPolicyCommand     = "com.jamfsoftware.jamf.checkforpolicies"
	maxJamfPolicyResponse = 8 << 20
)

// JamfPolicy contains only the metadata shown in the policy viewer.
type JamfPolicy struct {
	ID          int              `xml:"id"`
	Name        string           `xml:"name"`
	Scripts     []JamfScript     `xml:"scripts>script"`
	Packages    []JamfPolicyItem `xml:"packages>package"`
	Printers    []JamfPolicyItem `xml:"printers>printer"`
	Maintenance JamfMaintenance  `xml:"maintenanceSettings"`
	Restart     JamfRestart      `xml:"rebootSettings"`
}

type JamfScript struct {
	Filename string `xml:"filename"`
	Priority string `xml:"priority"`
}

type JamfPolicyItem struct {
	Name     string `xml:"name"`
	Filename string `xml:"filename"`
	Action   string `xml:"action"`
}

type JamfMaintenance struct {
	UpdateInventory   bool `xml:"updateInventory"`
	ResetComputerName bool `xml:"resetComputerName"`
	UpdatePrebindings bool `xml:"updatePrebindings"`
	FixPermissions    bool `xml:"fixPermissions"`
	SelfHealPackages  bool `xml:"selfHealPackages"`
	FixByHostFiles    bool `xml:"fixByHostFiles"`
	FlushSystemCache  bool `xml:"flushSystemCache"`
	FlushUserCache    bool `xml:"flushUserCache"`
	VerifyDisk        bool `xml:"verifyDisk"`
}

type JamfRestart struct {
	WithoutUser           bool `xml:"noUserReboot"`
	WithoutUserIfRequired bool `xml:"noUserRebootIfRequired"`
	WithUser              bool `xml:"userReboot"`
	WithUserNow           bool `xml:"userRebootNow"`
	WithUserIfRequired    bool `xml:"userRebootIfRequired"`
}

type JamfPolicyVersion struct {
	Policy   JamfPolicy
	LastSeen time.Time
}

type JamfPolicyHistory struct {
	Server   string
	Versions []JamfPolicyVersion // newest first
}

func (d *Device) JamfPolicies() (catalog []JamfPolicyHistory, err error) {
	err = d.boltDB.View(func(tx *bolt.Tx) error {
		catalog, err = readJamfPolicies(tx, d.UDID)
		return err
	})
	return catalog, err
}

func readJamfPolicies(tx *bolt.Tx, udid string) ([]JamfPolicyHistory, error) {
	var catalog []JamfPolicyHistory
	if data := BucketGet(tx, jamfPolicyBucket, udid); len(data) != 0 {
		if err := json.Unmarshal(data, &catalog); err != nil {
			return nil, fmt.Errorf("reading Jamf policy catalog: %w", err)
		}
	}
	for _, row := range catalog {
		if len(row.Versions) == 0 {
			return nil, errors.New("Jamf policy catalog contains an empty history")
		}
	}
	return catalog, nil
}

func sameJamfPolicy(a, b JamfPolicy) bool {
	return a.ID == b.ID && a.Name == b.Name &&
		slices.Equal(a.Scripts, b.Scripts) && slices.Equal(a.Packages, b.Packages) &&
		slices.Equal(a.Printers, b.Printers) && a.Maintenance == b.Maintenance && a.Restart == b.Restart
}

func (d *Device) mergeJamfPolicies(ctx context.Context, server string, policies []JamfPolicy, now time.Time) error {
	if len(policies) == 0 {
		return ctx.Err()
	}
	return d.boltDB.Update(func(tx *bolt.Tx) error {
		catalog, err := readJamfPolicies(tx, d.UDID)
		if err != nil {
			return err
		}
		type key struct {
			server string
			id     int
		}
		rows := make(map[key]int, len(catalog))
		for i, row := range catalog {
			rows[key{row.Server, row.Versions[0].Policy.ID}] = i
		}
		for _, policy := range policies {
			k := key{server, policy.ID}
			i, exists := rows[k]
			if !exists {
				i = len(catalog)
				catalog = append(catalog, JamfPolicyHistory{Server: server})
				rows[k] = i
			}
			row := &catalog[i]
			for j, old := range row.Versions {
				if sameJamfPolicy(old.Policy, policy) {
					row.Versions = append(row.Versions[:j], row.Versions[j+1:]...)
					break
				}
			}
			row.Versions = append([]JamfPolicyVersion{{Policy: policy, LastSeen: now}}, row.Versions...)
		}
		sort.Slice(catalog, func(i, j int) bool {
			a, b := catalog[i], catalog[j]
			if a.Server != b.Server {
				return a.Server < b.Server
			}
			return a.Versions[0].Policy.ID < b.Versions[0].Policy.ID
		})
		data, err := json.Marshal(catalog)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return BucketPutOrDelete(tx, jamfPolicyBucket, d.UDID, data)
	})
}

type jamfPolicyRequest struct {
	XMLName   xml.Name `xml:"jamf:jamfMessage"`
	Namespace string   `xml:"xmlns:jamf,attr"`
	Types     string   `xml:"xmlns:xsi,attr"`
	Device    struct {
		UUID         string   `xml:"uuid"`
		MACAddresses struct{} `xml:"macAddresses"`
		Name         string   `xml:"name"`
		Serial       string   `xml:"serialNumber"`
	} `xml:"device"`
	Application string `xml:"application"`
	Timestamp   int64  `xml:"messageTimestamp"`
	Content     struct {
		Type    string `xml:"xsi:type,attr"`
		UUID    string `xml:"uuid"`
		Command string `xml:"commandType"`
		Check   struct {
			Username string `xml:"jamf:username"`
			Trigger  string `xml:"jamf:trigger"`
			Day      string `xml:"jamf:day"`
			Hour     int    `xml:"jamf:hour"`
			Minute   int    `xml:"jamf:minute"`
			IP       string `xml:"jamf:reportedIP"`
			Version  string `xml:"jamf:version"`
		} `xml:"commandData>checkForPolicies"`
	} `xml:"content"`
}

// JamfPolicyEndpoint derives the client endpoint from a recognized Jamf MDM path.
func (c *MDMClient) JamfPolicyEndpoint() (string, error) {
	if !c.enrolled() {
		return "", errors.New("device is not enrolled")
	}
	server, err := url.Parse(c.MDMPayload.ServerURL)
	if err != nil || server.Scheme != "https" || server.Hostname() == "" || server.User != nil {
		return "", errors.New("Jamf policies require an HTTPS MDM server URL")
	}
	path := strings.TrimRight(server.Path, "/")
	for _, suffix := range []string{"/computer/mdm", "/mdm/ServerURL"} {
		if strings.HasSuffix(path, suffix) {
			server.Path = strings.TrimRight(strings.TrimSuffix(path, suffix), "/") + "/client"
			server.RawPath, server.RawQuery, server.Fragment, server.RawFragment = "", "", "", ""
			server.ForceQuery = false
			return server.String(), nil
		}
	}
	return "", errors.New("MDM profile does not have a recognized Jamf server path")
}

// RefreshJamfPolicies fetches one recurring check-in response and stores its metadata.
func (c *MDMClient) RefreshJamfPolicies(ctx context.Context, identity *JamfFrameworkIdentity) (int, error) {
	return c.refreshJamfPolicies(ctx, identity, http.DefaultTransport)
}

func (c *MDMClient) refreshJamfPolicies(ctx context.Context, identity *JamfFrameworkIdentity, transport http.RoundTripper) (int, error) {
	endpoint, err := c.JamfPolicyEndpoint()
	if err != nil {
		return 0, err
	}
	d := c.Device
	if err := identity.ValidateDevice(d.UDID); err != nil {
		return 0, err
	}
	inventory := d.QueryResponses()
	zone, _ := inventory["TimeZone"].(string)
	location, err := time.LoadLocation(zone)
	if err != nil {
		location = time.UTC
	}
	now := time.Now().In(location)
	var message jamfPolicyRequest
	message.Namespace = jamfNamespace
	message.Types = "http://www.w3.org/2001/XMLSchema-instance"
	message.Device.UUID, message.Device.Name, message.Device.Serial = d.UDID, d.ComputerName, d.Serial
	message.Application = "com.jamfsoftware.jamf"
	message.Timestamp = now.UnixMilli()
	message.Content.Type = "jamf:RequestContent"
	message.Content.UUID = strings.ToUpper(uuid.NewString())
	message.Content.Command = jamfPolicyCommand + "request"
	message.Content.Check.Trigger = "CLIENT_CHECKIN"
	message.Content.Check.Day, message.Content.Check.Hour, message.Content.Check.Minute = now.Format("Mon"), now.Hour(), now.Minute()
	message.Content.Check.Version, _ = inventory["JamfBinaryVersion"].(string)
	body, err := xml.Marshal(message)
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(body)
	signature, err := rsa.SignPKCS1v15(nil, identity.key, crypto.SHA256, digest[:])
	if err != nil {
		return 0, fmt.Errorf("signing Jamf check-in: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	req.Header.Set("JAMF-Device-Alg", "SHA256withRSA")
	req.Header.Set("JAMF-Device-Sig", base64.StdEncoding.EncodeToString(signature))
	req.Header.Set("User-Agent", "Mac OS X "+d.OSVersion+";")
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Jamf check-in returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJamfPolicyResponse+1))
	if err != nil {
		return 0, err
	}
	if len(raw) > maxJamfPolicyResponse {
		return 0, errors.New("Jamf policy response exceeds size limit")
	}
	policies, err := parseJamfPolicies(raw, message.Content.UUID)
	if err != nil {
		return 0, err
	}
	return len(policies), d.mergeJamfPolicies(ctx, endpoint, policies, time.Now().UTC())
}

func parseJamfPolicies(raw []byte, commandID string) ([]JamfPolicy, error) {
	var response struct {
		XMLName xml.Name `xml:"http://www.jamfsoftware.com/JAMFMessage jamfMessage"`
		Content []struct {
			ID       string `xml:"uuid"`
			Command  string `xml:"commandType"`
			Code     *int   `xml:"status>code"`
			Policies *struct {
				Items []JamfPolicy `xml:"policy"`
			} `xml:"commandData>checkForPolicies>policies"`
		} `xml:"content"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("invalid Jamf policy response: %w", err)
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		switch token := token.(type) {
		case xml.CharData:
			if err == nil && len(bytes.TrimSpace(token)) == 0 {
				continue
			}
		case xml.Comment:
			if err == nil {
				continue
			}
		}
		return nil, errors.New("unexpected data after Jamf policy response")
	}
	if len(response.Content) != 1 {
		return nil, errors.New("expected one Jamf policy response")
	}
	content := response.Content[0]
	if content.Code != nil && *content.Code != 0 {
		if *content.Code == 1501 {
			return nil, errors.New("Jamf rejected the device signature (1501)")
		}
		return nil, fmt.Errorf("Jamf check-in failed with status %d", *content.Code)
	}
	if !strings.EqualFold(content.ID, commandID) || content.Command != jamfPolicyCommand+"response" || content.Code == nil || content.Policies == nil {
		return nil, errors.New("Jamf response does not match the policy check-in")
	}
	seen := make(map[int]bool, len(content.Policies.Items))
	for _, policy := range content.Policies.Items {
		if policy.ID <= 0 || seen[policy.ID] {
			return nil, errors.New("invalid or duplicate Jamf policy ID")
		}
		seen[policy.ID] = true
	}
	return content.Policies.Items, nil
}
