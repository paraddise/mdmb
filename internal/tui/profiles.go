package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/jessepeterson/cfgprofiles"
	"github.com/jessepeterson/mdmb/internal/device"
)

type profileRow struct {
	id      string
	profile *cfgprofiles.Profile
	err     error
}

func enrolled(d *device.Device) bool {
	return d != nil && d.MDMProfileIdentifier != "" && d.MDMIdentityKeychainUUID != ""
}

func (m *model) reloadProfiles(selectedID string) {
	m.profiles = nil
	m.profileIndex = 0
	store := m.selected.SystemProfileStore()
	ids, err := store.ListUUIDs()
	if err != nil {
		m.status += " " + err.Error()
		return
	}
	for _, id := range ids {
		profile, err := store.Load(id)
		m.profiles = append(m.profiles, profileRow{id: id, profile: profile, err: err})
		if id == selectedID {
			m.profileIndex = len(m.profiles) - 1
		}
	}
}

func (m *model) openProfile() {
	if m.profileIndex >= len(m.profiles) {
		return
	}
	row := m.profiles[m.profileIndex]
	raw, err := m.selected.SystemProfileStore().Raw(row.id)
	if err != nil {
		m.status = err.Error()
		return
	}
	m.scepPayloads, m.scepIndex = nil, 0
	var description strings.Builder
	if row.err != nil {
		fmt.Fprintf(&description, "%s %s\n", profileErrorStyle.Render("Metadata:"), terminalText(row.err.Error(), false))
	} else {
		p := row.profile
		fmt.Fprintln(&description, titleStyle.Render(terminalText(displayName(p.PayloadDisplayName, row.id), false)))
		writeProfileField(&description, "Identifier", p.PayloadIdentifier)
		writeProfileField(&description, "UUID", p.PayloadUUID)
		writeProfileField(&description, "Organization", p.PayloadOrganization)
	}
	preview, err := m.selected.PreviewProfile(raw)
	switch {
	case err != nil && preview.Encrypted:
		fmt.Fprintf(&description, "\n%s\n%s %s", titleStyle.Render("Encrypted profile"),
			profileErrorStyle.Render("Could not decrypt payloads:"), terminalText(err.Error(), false))
	case err != nil:
		fmt.Fprintf(&description, "\n%s %s", profileErrorStyle.Render("Decoding plist:"), terminalText(err.Error(), false))
	default:
		if preview.Encrypted {
			fmt.Fprintln(&description, "\n"+mutedStyle.Render("Encrypted profile · decrypted with this device’s MDM identity"))
		}
		fmt.Fprintln(&description, "\n"+titleStyle.Render(fmt.Sprintf("Payloads (%d)", len(preview.Payloads))))
		for _, payload := range preview.Payloads {
			fmt.Fprintf(&description, "  %s  %s\n", markupStyle.Render(terminalText(payload.Type, false)), terminalText(payload.Identifier, false))
		}
		m.scepPayloads, err = m.selected.SCEPPayloads(row.id)
		if err != nil {
			fmt.Fprintf(&description, "\n%s %s\n", profileErrorStyle.Render("SCEP payloads:"), terminalText(err.Error(), false))
		}
		for _, payload := range m.scepPayloads {
			fmt.Fprintf(&description, "  SCEP %s · %s\n", terminalText(payload.Name, false), highlightedSCEPStatus(payload.Status))
		}
		fmt.Fprintf(&description, "\n%s\n%s", titleStyle.Render("Property list"), highlightXML(string(preview.XML)))
	}
	m.openStyledViewer(profileScreen, description.String())
}

var (
	profileErrorStyle   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#A12435", Dark: "#FF9CA7"})
	profileWarningStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#865400", Dark: "#FFD08A"})
)

func writeProfileField(out *strings.Builder, name, value string) {
	fmt.Fprintf(out, "%s %s\n", mutedStyle.Render(name+":"), terminalText(value, false))
}

func highlightedSCEPStatus(status device.SCEPStatus) string {
	text := terminalText(scepStatusText(status), false)
	switch status.State {
	case "Issued":
		return valueStyle.Render(text)
	case "Failed":
		return profileErrorStyle.Render(text)
	case "Cancelled", "Interrupted":
		return profileWarningStyle.Render(text)
	default:
		return mutedStyle.Render(text)
	}
}

func (m *model) exportProfile() {
	path := m.exportPath.Value()
	raw, err := m.selected.SystemProfileStore().Raw(m.profiles[m.profileIndex].id)
	if err == nil {
		err = writeProfile(path, raw)
	}
	if err != nil {
		m.status = "Export: " + err.Error()
		return
	}
	m.exportPath.Blur()
	m.screen, m.status = profileScreen, "Saved "+path
}

func writeProfile(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("enter a destination path")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}
