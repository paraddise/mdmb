package device

import (
	"bytes"
	"fmt"

	plist "github.com/groob/plist"
	"github.com/jessepeterson/cfgprofiles"
	"github.com/smallstep/pkcs7"
	howettPlist "howett.net/plist"
)

// binaryPlistMagic is the header of Apple binary property lists
// ("bplist00", "bplist01", ...).
var binaryPlistMagic = []byte("bplist")

// unmarshalPlist decodes a plist of unknown format into v.
//
// MDM servers may answer with either XML ("<?xml ...") or binary
// ("bplist00") property lists, so the format is detected from the
// leading magic bytes and the appropriate decoder is used. The
// howett.net/plist Unmarshal handles both formats transparently, but
// we keep an explicit format check here to produce clear errors for
// payloads that are not plists at all (e.g. plain HTTP error bodies).
func unmarshalPlist(data []byte, v interface{}) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return fmt.Errorf("empty plist payload")
	}
	switch {
	case bytes.HasPrefix(trimmed, binaryPlistMagic):
		// binary property list
	case bytes.HasPrefix(trimmed, []byte("<?xml")):
		// XML property list
	case trimmed[0] == 0x30:
		// CMS SignedData (BER, starts with SEQUENCE) — unwrap to get inner content
		inner, cmsErr := unwrapCMS(data)
		if cmsErr != nil {
			return fmt.Errorf("plist: CMS unwrap failed: %w (first bytes: %.20q)", cmsErr, trimmed)
		}
		if len(inner) == 0 {
			return fmt.Errorf("plist: CMS unwrapped to empty content")
		}
		// Recursively parse the unwrapped content
		return unmarshalPlist(inner, v)
	default:
		return fmt.Errorf("unrecognized plist format (expected bplist or <?xml header): %.20q", trimmed)
	}
	if _, err := howettPlist.Unmarshal(data, v); err != nil {
		return fmt.Errorf("plist decode: %w", err)
	}
	return nil
}

// unwrapCMS extracts the content from a CMS SignedData envelope.
// Returns the inner content bytes (which should be a plist).
func unwrapCMS(data []byte) ([]byte, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("pkcs7 parse: %w", err)
	}
	if p7.Content == nil {
		return nil, fmt.Errorf("CMS has no content")
	}
	return p7.Content, nil
}

// ProfileXML decodes a stored profile without dropping unrecognized payload keys.
func ProfileXML(data []byte) ([]byte, error) {
	var profile map[string]any
	if err := unmarshalPlist(data, &profile); err != nil {
		return nil, err
	}
	return howettPlist.MarshalIndent(profile, howettPlist.XMLFormat, "  ")
}

// cfgprofiles uses groob's payload-specific unmarshaling hooks.
func unmarshalProfile(data []byte, profile *cfgprofiles.Profile) error {
	xml, err := ProfileXML(data)
	if err != nil {
		return err
	}
	return plist.Unmarshal(xml, profile)
}
