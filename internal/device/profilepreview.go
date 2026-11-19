package device

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/smallstep/pkcs7"
	plist "howett.net/plist"
)

type ProfilePayloadSummary struct {
	Type       string
	Identifier string
}

type ProfilePreview struct {
	Encrypted bool
	Payloads  []ProfilePayloadSummary
	XML       []byte
}

// PreviewProfile decodes a profile for display, using this device's MDM
// identity to open EncryptedPayloadContent when present.
func (d *Device) PreviewProfile(data []byte) (ProfilePreview, error) {
	profile, encrypted, err := d.decodedProfile(data)
	preview := ProfilePreview{Encrypted: encrypted}
	if err != nil {
		return preview, err
	}
	payloads, _ := profile["PayloadContent"].([]any)
	for _, item := range payloads {
		payload, _ := item.(map[string]any)
		kind, _ := payload["PayloadType"].(string)
		identifier, _ := payload["PayloadIdentifier"].(string)
		preview.Payloads = append(preview.Payloads, ProfilePayloadSummary{Type: kind, Identifier: identifier})
	}
	preview.XML, err = plist.MarshalIndent(profile, plist.XMLFormat, "  ")
	return preview, err
}

func (d *Device) decodedProfile(data []byte) (map[string]any, bool, error) {
	var profile map[string]any
	if err := unmarshalPlist(data, &profile); err != nil {
		return nil, false, err
	}
	encrypted, ok := profile["EncryptedPayloadContent"]
	if !ok {
		return profile, false, nil
	}
	content, ok := encrypted.([]byte)
	if !ok || len(content) == 0 {
		return nil, true, errors.New("invalid EncryptedPayloadContent")
	}
	payloads, err := d.decryptProfilePayloads(content)
	if err != nil {
		return nil, true, err
	}
	delete(profile, "EncryptedPayloadContent")
	profile["PayloadContent"] = payloads
	return profile, true, nil
}

func (d *Device) decryptProfilePayloads(content []byte) ([]any, error) {
	cms, err := pkcs7.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("parsing encrypted CMS: %w", err)
	}
	cert, key, err := d.SystemKeychain().loadIdentity(d.MDMIdentityKeychainUUID)
	if err != nil {
		return nil, err
	}
	plain, err := decryptProfileCMS(cms, cert, key)
	if err != nil {
		return nil, fmt.Errorf("decrypting with the device's MDM identity: %w", err)
	}
	var payloads []any
	// The decrypted content can start directly with <array>, without a plist header.
	if _, err := plist.Unmarshal(plain, &payloads); err != nil {
		return nil, fmt.Errorf("decoding decrypted payloads: %w", err)
	}
	for _, payload := range payloads {
		if _, ok := payload.(map[string]any); !ok {
			return nil, errors.New("decrypted payload array contains a non-dictionary item")
		}
	}
	if payloads == nil {
		payloads = []any{}
	}
	return payloads, nil
}

// The CMS dependency can panic on malformed CBC ciphertext or padding.
func decryptProfileCMS(cms *pkcs7.PKCS7, cert *x509.Certificate, key *rsa.PrivateKey) (plain []byte, err error) {
	defer func() {
		if recover() != nil {
			plain, err = nil, errors.New("malformed CMS ciphertext")
		}
	}()
	return cms.Decrypt(cert, key)
}
