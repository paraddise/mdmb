package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *model) reloadCertificates(selectID string) {
	m.certificateIndex = 0
	certificates, err := m.selected.Certificates()
	if err != nil {
		m.status = err.Error()
	}
	m.certificates = certificates
	for i, certificate := range certificates {
		if certificate.UUID == selectID {
			m.certificateIndex = i
			break
		}
	}
}

func (m *model) certificatesView() string {
	if len(m.certificates) == 0 {
		return "No certificates in the System keychain."
	}
	from, to := visibleRows(m.certificateIndex, len(m.certificates), max(1, (m.height-9)/3))
	lines := []string{"System keychain"}
	for i := from; i < to; i++ {
		cert := m.certificates[i]
		name := cert.Name()
		if cert.MDMIdentity {
			name = "MDM identity · " + name
		}
		lines = append(lines, highlight(i == m.certificateIndex, name),
			"  Issuer  "+terminalText(cert.X509.Issuer.String(), false),
			fmt.Sprintf("  %s to %s", cert.X509.NotBefore.UTC().Format("2006-01-02"), cert.X509.NotAfter.UTC().Format("2006-01-02")))
	}
	return strings.Join(lines, "\n")
}

func (m *model) openCertificate() {
	m.certificateBack = m.screen
	m.certificatePEM = false
	m.showCertificate()
}

func (m *model) showCertificate() {
	content := m.certificates[m.certificateIndex].Text()
	if m.certificatePEM {
		content = string(m.certificates[m.certificateIndex].PEM())
	}
	m.openViewer(certificateScreen, content)
}

func (m *model) certificateExtension() string {
	if m.certificatePEM {
		return ".pem"
	}
	return ".txt"
}

func (m *model) startExport(filename string) tea.Cmd {
	m.exportPath.SetValue(filename)
	m.exportPath.CursorEnd()
	m.exportBack = m.screen
	m.screen, m.status = exportScreen, ""
	return m.exportPath.Focus()
}

func (m *model) exportCertificate() {
	path := m.exportPath.Value()
	cert := m.certificates[m.certificateIndex]
	data := []byte(cert.Text())
	if m.certificatePEM {
		data = cert.PEM()
	}
	if err := writeProfile(path, data); err != nil {
		m.status = "Export: " + err.Error()
		return
	}
	m.exportPath.Blur()
	m.screen, m.status = certificateScreen, "Saved "+path
}
