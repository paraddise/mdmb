package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#08575A", Dark: "#78E0D6"})
	mutedStyle    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#4E5766", Dark: "#A8B5C8"})
	selectedStyle = lipgloss.NewStyle().Bold(true).Reverse(true)
)

func (m *model) View() string {
	if m.width < 34 || m.height < 12 {
		return "Resize terminal to at least 34 × 12"
	}
	title, body, help := m.screenContent()
	if m.cancelOperation != nil {
		help = "Esc  Cancel " + m.busyLabel + "    Ctrl+C  Quit"
	}
	width := m.width - 4
	line := func(text string) string { return "  " + ansi.Truncate(text, width, "…") }
	lines := []string{"", line(titleStyle.Render("mdmb  /  " + title)), "", ""}
	bodyLines := strings.Split(body, "\n")
	for _, row := range bodyLines[:min(len(bodyLines), m.height-8)] {
		lines = append(lines, line(row))
	}
	for len(lines) < m.height-4 {
		lines = append(lines, "")
	}
	lines = append(lines, "", line(terminalText(m.status, false)))
	for _, hint := range strings.Split(help, "\n") {
		lines = append(lines, line(mutedStyle.Render(hint)))
	}
	return strings.Join(lines, "\n")
}

func (m *model) screenContent() (string, string, string) {
	switch m.screen {
	case devicesScreen:
		return "Devices", m.devicesView(), "↑↓ Move    Enter Open    / Search    n New    q Quit"
	case deviceScreen:
		return "Device", m.deviceView(), "i Edit JSON    v MDM values    p Profiles    k Certificates\nj Policies    c Poll MDM    a Auto SCEP    l Log    Esc Back"
	case editorScreen:
		return "Inventory JSON", m.editor.View(), "Ctrl+S Save    Esc Back"
	case discardScreen:
		return "Inventory JSON", "Discard unsaved changes?", "y Discard    n Keep editing"
	case profilesScreen:
		return "Profiles", m.profilesView(), "↑↓ Move    Enter View    c Poll MDM    l Log    Esc Back"
	case profileScreen:
		help := "↑↓ Scroll    e Export    l Log    Esc Back"
		if len(m.scepPayloads) > 0 {
			help = "s SCEP payloads    e Export    l Log    Esc Back"
		}
		return "Profile", m.viewer.View(), help
	case certificatesScreen:
		return "Certificates", m.certificatesView(), "↑↓ Move    Enter View    Esc Back"
	case certificateScreen:
		return "Certificate " + m.certificateExtension(), m.viewer.View(), "↑↓ Scroll    t Text/PEM    e Export    Esc Back"
	case scepScreen:
		return "SCEP payloads", m.scepView(), "↑↓ Move    e Enroll    Enter Certificate    l Log    Esc Back"
	case confirmEnrollScreen:
		payload := m.scepPayloads[m.scepIndex]
		body := "Server   " + terminalText(payload.Host, false) + "\nPayload  " + terminalText(payload.Name, false)
		return "Confirm SCEP enrollment", ansi.Hardwrap(body, m.width-4, true), "Enter Enroll    Esc Cancel"
	case exportScreen:
		ext := ".mobileconfig"
		if m.exportBack == certificateScreen {
			ext = m.certificateExtension()
		}
		return "Export " + ext, "Destination path\n\n" + m.exportPath.View(), "Enter Export    Esc Cancel"
	case jamfPoliciesScreen:
		return "Policies", m.jamfPoliciesView(), "↑↓ Move    Enter View    r Refresh    Esc Back"
	case jamfPolicyScreen:
		return "Jamf policy", m.viewer.View(), "↑↓ Scroll    Esc Back"
	case confirmJamfScreen:
		body := terminalText(m.selected.ComputerName, false) + "\n" + terminalText(m.jamfEndpoint, false) +
			"\nJamf may update inventory and mark policies as running."
		return "Confirm Jamf check-in", ansi.Hardwrap(body, m.width-4, true), "Enter Check in    Esc Cancel"
	case effectiveScreen:
		return "Effective MDM inventory", m.viewer.View(), "↑↓ Scroll    Esc Back"
	case diagnosticsScreen:
		if strings.TrimSpace(m.diagnostics) == "" {
			return "Diagnostics", "No diagnostics for this device in this session.", "Esc Back"
		}
		return "Diagnostics", m.viewer.View(), "↑↓ Scroll    Esc Back"
	default:
		return "", "", ""
	}
}

func (m *model) devicesView() string {
	rows := m.filteredDevices()
	filter := "All devices"
	if m.searching {
		filter = m.search.View()
	} else if m.search.Value() != "" {
		filter = "Search: " + terminalText(m.search.Value(), false)
	}
	if len(m.devices) == 0 {
		return "No devices yet. Press n to create one."
	}
	lines := []string{fmt.Sprintf("%s    %d device(s)", filter, len(rows)), ""}
	if len(rows) == 0 {
		return strings.Join(append(lines, "No matching devices."), "\n")
	}
	from, to := visibleRows(m.deviceIndex, len(rows), max(1, (m.height-10)/2))
	for i := from; i < to; i++ {
		d := rows[i]
		name := displayName(d.ComputerName, "Unnamed device")
		line := fmt.Sprintf("%s  ·  %s", name, enrollmentText(enrolled(d)))
		meta := fmt.Sprintf("%s  ·  OS %s  ·  %s", d.Serial, d.OSVersion, d.UDID)
		lines = append(lines, highlight(i == m.deviceIndex, line), "  "+terminalText(meta, false))
	}
	return strings.Join(lines, "\n")
}

func (m *model) deviceView() string {
	d := m.selected
	return terminalText(fmt.Sprintf("%s\nMDM          %s\nAuto SCEP Enroll  %s\nUDID         %s\nSerial       %s\nProduct      %s\nOS           %s\nBuild        %s",
		displayName(d.ComputerName, "Unnamed device"), enrollmentText(enrolled(d)), onOff(m.autoSCEP), d.UDID, d.Serial, d.ProductName, d.OSVersion, d.BuildVersion), true)
}

func (m *model) profilesView() string {
	if len(m.profiles) == 0 {
		return "No installed profiles."
	}
	from, to := visibleRows(m.profileIndex, len(m.profiles), max(1, m.height-9))
	lines := []string{fmt.Sprintf("%d installed profile(s)", len(m.profiles))}
	for i := from; i < to; i++ {
		row := m.profiles[i]
		label := row.id
		if row.err == nil {
			if name := row.profile.PayloadDisplayName; name != "" {
				label = name + "  ·  " + row.id
			}
			if len(row.profile.EncryptedPayloadContent) > 0 {
				label += "  ·  Encrypted"
			}
		} else {
			label += "  ·  decode error"
		}
		lines = append(lines, highlight(i == m.profileIndex, label))
	}
	return strings.Join(lines, "\n")
}

func visibleRows(index, count, capacity int) (int, int) {
	from := max(0, index-capacity+1)
	return from, min(count, from+capacity)
}

func highlight(selected bool, text string) string {
	text = terminalText(text, false)
	if selected {
		return selectedStyle.Render("› " + text)
	}
	return "  " + text
}

func displayName(name, fallback string) string {
	if name == "" {
		return fallback
	}
	return name
}

func enrollmentText(isEnrolled bool) string {
	if isEnrolled {
		return "Enrolled"
	}
	return "Not enrolled"
}
