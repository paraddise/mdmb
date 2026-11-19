package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jessepeterson/mdmb/internal/diagnostics"
	bolt "go.etcd.io/bbolt"
)

const declarativeBucket = "device_declarative_state"
const maxDeclarativeBody = 4 << 20

type declarativeManagementResponse struct {
	ConnectRequest
	token string
}

type declarativeCheckIn struct {
	MessageType string
	UDID        string
	Endpoint    string
	Data        []byte `plist:",omitempty"`
}

type declarativeTokens struct {
	SyncTokens struct{ DeclarationsToken string }
}

type declarationDescriptor struct {
	Identifier  string
	ServerToken string
}

type declarativeManifest struct {
	DeclarationsToken string
	Declarations      struct {
		Activations    []declarationDescriptor
		Configurations []declarationDescriptor
		Assets         []declarationDescriptor
		Management     []declarationDescriptor
	}
}

type cachedDeclaration struct {
	declarationDescriptor
	Data json.RawMessage
}

type declarativeState struct {
	Token         string
	Declarations  map[string][]cachedDeclaration
	StatusPending bool
}

func declarativeCommandToken(command map[string]any) (string, error) {
	raw, exists := command["Data"]
	if !exists {
		return "", nil
	}
	data, ok := raw.([]byte)
	if !ok {
		return "", fmt.Errorf("%w: Data must contain a JSON tokens response", errCommandFormat)
	}
	token, err := parseDeclarativeToken(data)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errCommandFormat, err)
	}
	return token, nil
}

func parseDeclarativeToken(data []byte) (string, error) {
	var parsed declarativeTokens
	if err := json.Unmarshal(data, &parsed); err != nil || !validDeclarationToken(parsed.SyncTokens.DeclarationsToken) {
		return "", errors.New("invalid declarative synchronization token")
	}
	return parsed.SyncTokens.DeclarationsToken, nil
}

func validDeclarationToken(token string) bool {
	return len(token) > 0 && len(token) <= 256
}

func (c *MDMClient) checkInDeclarative(ctx context.Context, endpoint string, data []byte) (int, []byte, error) {
	encoded, err := PlistReader(declarativeCheckIn{
		MessageType: "DeclarativeManagement", UDID: c.Device.UDID, Endpoint: endpoint, Data: data,
	})
	if err != nil {
		return 0, nil, err
	}
	resp, err := c.transport.DoCheckIn(ctx, encoded)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && strings.HasPrefix(endpoint, "declaration/") {
		return resp.StatusCode, nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, fmt.Errorf("declarative check-in returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDeclarativeBody+1))
	if len(raw) > maxDeclarativeBody {
		return resp.StatusCode, nil, errors.New("declarative response exceeds size limit")
	}
	return resp.StatusCode, raw, err
}

func (c *MDMClient) synchronizeDeclarative(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c.declarativeMu.Lock()
	defer c.declarativeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	state, err := c.loadDeclarativeState()
	if err != nil {
		return err
	}
	if token == "" {
		_, raw, err := c.checkInDeclarative(ctx, "tokens", nil)
		if err != nil {
			return err
		}
		token, err = parseDeclarativeToken(raw)
		if err != nil {
			return err
		}
	}
	if token != state.Token {
		state, err = c.fetchDeclarativeState(ctx, state)
		if err != nil {
			return err
		}
		if err := c.saveDeclarativeState(state); err != nil {
			return err
		}
	}
	if !state.StatusPending {
		return nil
	}
	if err := c.reportDeclarativeState(ctx, state); err != nil {
		return err
	}
	state.StatusPending = false
	return c.saveDeclarativeState(state)
}

func (c *MDMClient) loadDeclarativeState() (state declarativeState, err error) {
	err = c.Device.boltDB.View(func(tx *bolt.Tx) error {
		if raw := BucketGet(tx, declarativeBucket, c.Device.UDID); len(raw) != 0 {
			return json.Unmarshal(raw, &state)
		}
		return nil
	})
	return
}

func (c *MDMClient) saveDeclarativeState(state declarativeState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return c.Device.boltDB.Update(func(tx *bolt.Tx) error {
		return BucketPutOrDelete(tx, declarativeBucket, c.Device.UDID, raw)
	})
}

func (c *MDMClient) fetchDeclarativeState(ctx context.Context, previous declarativeState) (declarativeState, error) {
	_, raw, err := c.checkInDeclarative(ctx, "declaration-items", nil)
	if err != nil {
		return declarativeState{}, err
	}
	var manifest declarativeManifest
	if err := json.Unmarshal(raw, &manifest); err != nil || !validDeclarationToken(manifest.DeclarationsToken) {
		return declarativeState{}, errors.New("invalid declarative manifest")
	}
	groups := []struct {
		kind  string
		items []declarationDescriptor
	}{
		{"activation", manifest.Declarations.Activations},
		{"configuration", manifest.Declarations.Configurations},
		{"asset", manifest.Declarations.Assets},
		{"management", manifest.Declarations.Management},
	}
	state := declarativeState{Token: manifest.DeclarationsToken, Declarations: map[string][]cachedDeclaration{}, StatusPending: true}
	for _, group := range groups {
		if group.items == nil {
			return declarativeState{}, errors.New("declarative manifest is missing a declaration group")
		}
		existing := map[string]cachedDeclaration{}
		for _, item := range previous.Declarations[group.kind] {
			existing[item.Identifier] = item
		}
		seen := map[string]bool{}
		for _, descriptor := range group.items {
			if descriptor.Identifier == "" || descriptor.ServerToken == "" || seen[descriptor.Identifier] {
				return declarativeState{}, errors.New("invalid or duplicate declaration descriptor")
			}
			seen[descriptor.Identifier] = true
			if cached := existing[descriptor.Identifier]; cached.ServerToken == descriptor.ServerToken {
				state.Declarations[group.kind] = append(state.Declarations[group.kind], cached)
				continue
			}
			endpoint := "declaration/" + group.kind + "/" + url.PathEscape(descriptor.Identifier)
			code, body, err := c.checkInDeclarative(ctx, endpoint, nil)
			if err != nil {
				return declarativeState{}, err
			}
			if code == http.StatusNotFound {
				continue
			}
			var bodyHeader struct {
				declarationDescriptor
				Type    string
				Payload map[string]json.RawMessage
			}
			if err := json.Unmarshal(body, &bodyHeader); err != nil || bodyHeader.declarationDescriptor != descriptor ||
				!strings.HasPrefix(bodyHeader.Type, "com.apple."+group.kind+".") || bodyHeader.Payload == nil {
				return declarativeState{}, errors.New("declaration does not match the manifest")
			}
			state.Declarations[group.kind] = append(state.Declarations[group.kind], cachedDeclaration{descriptor, body})
		}
	}
	return state, nil
}

func (c *MDMClient) reportDeclarativeState(ctx context.Context, state declarativeState) error {
	type declarationStatus struct {
		Identifier  string `json:"identifier"`
		ServerToken string `json:"server-token"`
		Active      bool   `json:"active"`
		Valid       string `json:"valid"`
	}
	report := map[string][]declarationStatus{}
	for kind, field := range map[string]string{"activation": "activations", "configuration": "configurations", "asset": "assets", "management": "management"} {
		report[field] = []declarationStatus{}
		for _, item := range state.Declarations[kind] {
			report[field] = append(report[field], declarationStatus{Identifier: item.Identifier, ServerToken: item.ServerToken, Valid: "unknown"})
		}
	}
	raw, err := json.Marshal(map[string]any{"StatusItems": map[string]any{"management": map[string]any{"declarations": report}}, "Errors": []any{}})
	if err != nil {
		return err
	}
	_, _, err = c.checkInDeclarative(ctx, "status", raw)
	return err
}

func (c *MDMClient) afterDeclarativeAcknowledgment(ctx context.Context, token string) {
	if err := c.synchronizeDeclarative(ctx, token); err != nil {
		diagnostics.Printf(ctx, os.Stderr, "DDM synchronization: %v\n", err)
	}
}
