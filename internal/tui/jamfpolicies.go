package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/jessepeterson/mdmb/internal/device"
)

type jamfPolicyResult struct {
	count int
	err   error
}

func (m *model) reloadJamfPolicies() {
	rows, err := m.selected.JamfPolicies()
	if err != nil {
		m.status = err.Error()
		return
	}
	m.jamfPolicies = rows
	m.jamfPolicyIndex = min(m.jamfPolicyIndex, max(0, len(rows)-1))
}

func (m *model) jamfPoliciesKey(key string) tea.Cmd {
	switch key {
	case "esc", "backspace":
		m.screen, m.status = deviceScreen, ""
	case "up", "k":
		m.jamfPolicyIndex = max(0, m.jamfPolicyIndex-1)
	case "down", "j":
		m.jamfPolicyIndex = moveDown(m.jamfPolicyIndex, len(m.jamfPolicies))
	case "enter":
		if len(m.jamfPolicies) > 0 {
			m.openViewer(jamfPolicyScreen, jamfPolicyDetails(m.jamfPolicies[m.jamfPolicyIndex]))
		}
	case "r":
		client, err := m.selected.MDMClient()
		if err == nil {
			m.jamfEndpoint, err = client.JamfPolicyEndpoint()
		}
		if err == nil {
			err = m.jamfIdentity.ValidateDevice(m.deviceID)
		}
		if err != nil {
			m.status = "Jamf: " + err.Error()
			return nil
		}
		m.screen, m.status = confirmJamfScreen, ""
	}
	return nil
}

func (m *model) startJamfPolicyRefresh() tea.Cmd {
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	m.cancelOperation = cancel
	m.busyLabel = "Jamf check-in"
	m.screen, m.status = jamfPoliciesScreen, "Checking for Jamf policies…"
	id, db, endpoint, identity := m.deviceID, m.db, m.jamfEndpoint, m.jamfIdentity
	return func() tea.Msg {
		m.operationLock.Lock()
		defer m.operationLock.Unlock()
		defer cancel()
		if err := ctx.Err(); err != nil {
			return jamfPolicyResult{err: err}
		}
		d, err := device.Load(id, db)
		if err != nil {
			return jamfPolicyResult{err: err}
		}
		client, err := d.MDMClient()
		if err != nil {
			return jamfPolicyResult{err: err}
		}
		currentEndpoint, err := client.JamfPolicyEndpoint()
		if err != nil {
			return jamfPolicyResult{err: err}
		}
		if currentEndpoint != endpoint {
			return jamfPolicyResult{err: errors.New("Jamf server changed. Confirm the new server to refresh.")}
		}
		count, err := client.RefreshJamfPolicies(ctx, identity)
		return jamfPolicyResult{count: count, err: err}
	}
}

func (m *model) finishJamfPolicyRefresh(result jamfPolicyResult) {
	m.cancelOperation = nil
	switch {
	case errors.Is(result.err, context.Canceled):
		m.status = "Jamf check-in cancelled"
	case errors.Is(result.err, context.DeadlineExceeded):
		m.status = "Jamf check-in timed out"
	case result.err != nil:
		m.status = "Jamf: " + result.err.Error()
	default:
		m.status = fmt.Sprintf("Jamf returned %d policies", result.count)
		m.reloadJamfPolicies()
	}
}

func (m *model) jamfPoliciesView() string {
	if len(m.jamfPolicies) == 0 {
		return "No policies collected. Press r to refresh."
	}
	from, to := visibleRows(m.jamfPolicyIndex, len(m.jamfPolicies), max(1, m.height-9))
	lines := []string{fmt.Sprintf("%d collected policies", len(m.jamfPolicies))}
	for i := from; i < to; i++ {
		row := m.jamfPolicies[i]
		policy := row.Versions[0].Policy
		label := fmt.Sprintf("%s  ·  #%d  ·  %s", displayName(policy.Name, "Unnamed policy"), policy.ID, row.Server)
		lines = append(lines, highlight(i == m.jamfPolicyIndex, label))
	}
	return strings.Join(lines, "\n")
}

func jamfPolicyDetails(row device.JamfPolicyHistory) string {
	var details strings.Builder
	fmt.Fprintln(&details, terminalText(row.Server, false))
	for _, version := range row.Versions {
		policy := version.Policy
		fmt.Fprintf(&details, "\n%s  ·  #%d\n", terminalText(displayName(policy.Name, "Unnamed policy"), false), policy.ID)
		fmt.Fprintf(&details, "Last seen %s\n", version.LastSeen.Format(time.RFC3339))
		for i, script := range policy.Scripts {
			fmt.Fprintf(&details, "Script %d  %s", i+1, terminalText(script.Filename, false))
			if script.Priority != "" {
				fmt.Fprintf(&details, "  ·  %s", terminalText(script.Priority, false))
			}
			fmt.Fprintln(&details)
		}
		for _, item := range policy.Packages {
			fmt.Fprintf(&details, "Package  %s  ·  %s\n", terminalText(displayName(item.Name, item.Filename), false), terminalText(item.Action, false))
		}
		for _, item := range policy.Printers {
			fmt.Fprintf(&details, "Printer  %s  ·  %s\n", terminalText(item.Name, false), terminalText(item.Action, false))
		}
		maintenance := policy.Maintenance
		restart := policy.Restart
		for _, action := range []struct {
			enabled bool
			label   string
		}{
			{maintenance.UpdateInventory, "Maintenance  Update inventory"},
			{maintenance.ResetComputerName, "Maintenance  Reset computer name"},
			{maintenance.UpdatePrebindings, "Maintenance  Update prebindings"},
			{maintenance.FixPermissions, "Maintenance  Repair permissions"},
			{maintenance.SelfHealPackages, "Maintenance  Repair packages"},
			{maintenance.FixByHostFiles, "Maintenance  Fix ByHost files"},
			{maintenance.FlushSystemCache, "Maintenance  Flush system cache"},
			{maintenance.FlushUserCache, "Maintenance  Flush user cache"},
			{maintenance.VerifyDisk, "Maintenance  Verify disk"},
			{restart.WithoutUser, "Restart  No user logged in"},
			{restart.WithoutUserIfRequired, "Restart  If required with no user logged in"},
			{restart.WithUser, "Restart  User logged in"},
			{restart.WithUserNow, "Restart  Immediately with user logged in"},
			{restart.WithUserIfRequired, "Restart  If required with user logged in"},
		} {
			if action.enabled {
				fmt.Fprintln(&details, action.label)
			}
		}
	}
	return details.String()
}
