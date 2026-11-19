package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/jessepeterson/mdmb/internal/device"
	"github.com/jessepeterson/mdmb/internal/diagnostics"
)

func onOff(enabled bool) string {
	if enabled {
		return "On"
	}
	return "Off"
}

func scepStatusText(status device.SCEPStatus) string {
	if status.Error != "" {
		return status.State + " · " + status.Error
	}
	if status.CertificateUUID != "" {
		return status.State + " · " + status.CertificateUUID
	}
	return status.State
}

func (m *model) scepView() string {
	from, to := visibleRows(m.scepIndex, len(m.scepPayloads), max(1, (m.height-9)/2))
	lines := []string{"Select a SCEP payload"}
	for i := from; i < to; i++ {
		payload := m.scepPayloads[i]
		lines = append(lines, highlight(i == m.scepIndex, payload.Name),
			"  "+highlightedSCEPStatus(payload.Status))
	}
	return strings.Join(lines, "\n")
}

func (m *model) handleSCEPKey(key string) tea.Cmd {
	switch key {
	case "esc", "backspace":
		m.openProfile()
	case "up", "k":
		m.scepIndex = max(0, m.scepIndex-1)
	case "down", "j":
		m.scepIndex = moveDown(m.scepIndex, len(m.scepPayloads))
	case "l":
		m.openViewer(diagnosticsScreen, m.diagnostics)
	case "e":
		if len(m.scepPayloads) == 0 {
			return nil
		}
		payload := m.scepPayloads[m.scepIndex]
		switch {
		case payload.Status.State == "Issued":
			m.status = "Certificate already issued · Enter to view"
		case payload.Host == "":
			m.status = "SCEP payload has no valid server host"
		default:
			m.screen, m.status = confirmEnrollScreen, ""
		}
	case "enter":
		if len(m.scepPayloads) == 0 {
			return nil
		}
		id := m.scepPayloads[m.scepIndex].Status.CertificateUUID
		if id == "" {
			return nil
		}
		m.reloadCertificates(id)
		if len(m.certificates) > 0 && m.certificates[m.certificateIndex].UUID == id {
			m.openCertificate()
		} else {
			m.status = "Issued certificate could not be loaded"
		}
	}
	return nil
}

type enrollResult struct {
	version string
	err     error
	log     string
}

func (m *model) startEnroll() tea.Cmd {
	profileID := m.profiles[m.profileIndex].id
	payload := m.scepPayloads[m.scepIndex]
	d := m.selected
	ctx, cancel := context.WithTimeout(m.ctx, time.Minute)
	m.cancelOperation, m.busyLabel = cancel, "SCEP enrollment"
	m.screen, m.status = scepScreen, "Enrolling "+payload.Name+"… Esc cancels"
	return func() tea.Msg {
		m.operationLock.Lock()
		defer m.operationLock.Unlock()
		defer cancel()
		if err := m.ctx.Err(); err != nil {
			return enrollResult{version: payload.Version, err: err}
		}
		var output pollLog
		_, err := d.EnrollSCEP(diagnostics.WithOutput(ctx, &output), profileID, payload.Version)
		return enrollResult{version: payload.Version, err: err, log: output.String()}
	}
}

func (m *model) finishEnroll(result enrollResult) {
	m.cancelOperation = nil
	m.openProfile()
	m.screen = scepScreen
	for i, payload := range m.scepPayloads {
		if payload.Version == result.version {
			m.scepIndex = i
			break
		}
	}
	if len(m.scepPayloads) == 0 {
		m.screen = profileScreen
	}
	m.reloadCertificates("")
	m.diagnostics += result.log
	m.status = "SCEP certificate issued"
	if result.err != nil {
		m.status = fmt.Sprintf("SCEP: %v", result.err)
		m.diagnostics += m.status + "\n"
	}
}
