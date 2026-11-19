package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/jessepeterson/mdmb/internal/device"
)

func TestJamfPoliciesNavigation(t *testing.T) {
	db := openTestDB(t, filepath.Join(t.TempDir(), "test.db"))
	d := createDevice(t, db, "Test Mac")
	m := newModel(db, context.Background())
	m.openDevice(d.UDID)
	key := func(s string) tea.Cmd {
		return m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
	}
	if cmd := key("j"); cmd != nil || m.screen != jamfPoliciesScreen || !strings.Contains(m.View(), "No policies collected") {
		t.Fatal("opening Jamf Policies should display the local catalog")
	}
	if cmd := key("r"); cmd != nil || !strings.Contains(m.status, "not enrolled") {
		t.Fatal("unenrolled device should have an explanatory refresh error")
	}
	m.jamfPolicies = []device.JamfPolicyHistory{{Server: "https://jamf.example/client", Versions: []device.JamfPolicyVersion{{
		Policy: device.JamfPolicy{ID: 7, Name: "Setup", Scripts: []device.JamfScript{{Filename: "setup.sh", Priority: "Before"}}},
	}}}}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != jamfPolicyScreen || !strings.Contains(m.View(), "setup.sh") {
		t.Fatal("opening a policy should show script metadata")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.screen != jamfPoliciesScreen {
		t.Fatal("closing a policy should return to the catalog")
	}
}
