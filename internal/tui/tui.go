package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/jessepeterson/mdmb/internal/device"
	"github.com/jessepeterson/mdmb/internal/diagnostics"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/term"
)

func Run(path string, identity *device.JamfFrameworkIdentity) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("tui requires an interactive terminal")
	}
	db, err := bolt.Open(path, 0644, &bolt.Options{Timeout: time.Second})
	if errors.Is(err, bolt.ErrTimeout) {
		return fmt.Errorf("database %s is locked by another process", path)
	}
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	m := newModel(db, ctx)
	m.jamfIdentity = identity
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	cancel()
	// Wait for an active operation before releasing the database, including on a signal.
	m.operationLock.Lock()
	m.operationLock.Unlock()
	return err
}

type screen int

const (
	devicesScreen screen = iota
	deviceScreen
	editorScreen
	discardScreen
	profilesScreen
	profileScreen
	exportScreen
	effectiveScreen
	diagnosticsScreen
	certificatesScreen
	certificateScreen
	scepScreen
	confirmEnrollScreen
	jamfPoliciesScreen
	jamfPolicyScreen
	confirmJamfScreen
)

type model struct {
	db               *bolt.DB
	ctx              context.Context
	operationLock    sync.Mutex
	cancelOperation  context.CancelFunc
	busyLabel        string
	diagnostics      string
	screen           screen
	width, height    int
	status           string
	devices          []*device.Device
	searching        bool
	search           textinput.Model
	deviceIndex      int
	deviceID         string
	selected         *device.Device
	profiles         []profileRow
	profileIndex     int
	editor           textarea.Model
	initialJSON      string
	viewer           viewport.Model
	viewText         string
	viewerBack       screen
	exportPath       textinput.Model
	exportBack       screen
	certificateBack  screen
	certificates     []device.Certificate
	certificateIndex int
	certificatePEM   bool
	scepPayloads     []device.SCEPPayload
	scepIndex        int
	jamfPolicies     []device.JamfPolicyHistory
	jamfPolicyIndex  int
	jamfEndpoint     string
	jamfIdentity     *device.JamfFrameworkIdentity
	autoSCEP         bool
}

func newModel(db *bolt.DB, ctx context.Context) *model {
	m := &model{db: db, ctx: ctx, width: 80, height: 24}
	m.search = textinput.New()
	m.search.Placeholder = "Name, serial or UDID"
	m.exportPath = textinput.New()
	m.editor = textarea.New()
	m.editor.CharLimit = 0
	m.editor.MaxHeight = 0
	m.viewer = viewport.New(76, 16)
	m.reloadDevices()
	return m
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) reloadDevices() {
	ids, err := device.List(m.db)
	if err != nil && !errors.Is(err, device.ErrNoDevices) {
		m.status = err.Error()
		return
	}
	m.devices = nil
	for _, id := range ids {
		d, err := device.Load(id, m.db)
		if err != nil {
			m.status = err.Error()
			continue
		}
		m.devices = append(m.devices, d)
	}
}

func (m *model) filteredDevices() []*device.Device {
	query := strings.ToLower(strings.TrimSpace(m.search.Value()))
	if query == "" {
		return m.devices
	}
	var matches []*device.Device
	for _, d := range m.devices {
		if strings.Contains(strings.ToLower(d.UDID+" "+d.Serial+" "+d.ComputerName), query) {
			matches = append(matches, d)
		}
	}
	return matches
}

func (m *model) openDevice(id string) {
	d, err := device.Load(id, m.db)
	if err != nil {
		m.status = err.Error()
		return
	}
	m.deviceID, m.selected = id, d
	m.diagnostics = ""
	m.profiles, m.profileIndex = nil, 0
	m.jamfPolicies, m.jamfPolicyIndex = nil, 0
	m.certificates, m.certificateIndex = nil, 0
	m.autoSCEP, err = d.AutoSCEPEnroll()
	if err != nil {
		m.status = err.Error()
	}
	m.screen = deviceScreen
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.editor.SetWidth(max(1, m.width-4))
		m.editor.SetHeight(max(1, m.height-8))
		m.viewer.Width, m.viewer.Height = max(1, m.width-4), max(1, m.height-8)
		m.viewer.SetContent(wrapViewerText(m.viewText, m.viewer.Width))
		m.search.Width, m.exportPath.Width = max(1, m.width-6), max(1, m.width-6)
	case pollResult:
		m.finishPoll(msg)
	case enrollResult:
		m.finishEnroll(msg)
	case jamfPolicyResult:
		m.finishJamfPolicyRefresh(msg)
	case tea.KeyMsg:
		return m, m.handleKey(msg)
	default:
		return m, m.updateInput(msg)
	}
	return m, nil
}

func (m *model) updateInput(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch {
	case m.screen == editorScreen:
		m.editor, cmd = m.editor.Update(msg)
	case m.screen == exportScreen:
		m.exportPath, cmd = m.exportPath.Update(msg)
	case m.screen == devicesScreen && m.searching:
		previous := m.search.Value()
		m.search, cmd = m.search.Update(msg)
		if previous != m.search.Value() {
			m.deviceIndex = 0
		}
	case m.screen == profileScreen || m.screen == effectiveScreen || m.screen == diagnosticsScreen || m.screen == certificateScreen || m.screen == jamfPolicyScreen:
		m.viewer, cmd = m.viewer.Update(msg)
	}
	return cmd
}

func (m *model) handleKey(msg tea.KeyMsg) tea.Cmd {
	key := msg.String()
	if key == "ctrl+c" {
		if m.cancelOperation != nil {
			m.cancelOperation()
		}
		return tea.Quit
	}
	if m.cancelOperation != nil {
		if key == "esc" {
			m.cancelOperation()
			m.status = "Cancelling " + m.busyLabel + "…"
		}
		return nil
	}
	switch m.screen {
	case devicesScreen:
		return m.devicesKey(msg)
	case deviceScreen:
		switch key {
		case "esc", "backspace":
			m.screen, m.status = devicesScreen, ""
		case "i":
			return m.openEditor()
		case "v":
			m.showJSON(map[string]any{
				"QueryResponses": m.selected.QueryResponses(),
				"SecurityInfo":   m.selected.EffectiveSecurityInfo(),
			})
		case "p":
			m.status = ""
			m.reloadProfiles("")
			m.screen = profilesScreen
		case "j":
			m.screen, m.status = jamfPoliciesScreen, ""
			m.reloadJamfPolicies()
		case "c":
			return m.startPoll()
		case "l":
			m.openViewer(diagnosticsScreen, m.diagnostics)
		case "k":
			m.status = ""
			m.reloadCertificates("")
			m.screen = certificatesScreen
		case "a":
			if err := m.selected.SetAutoSCEPEnroll(!m.autoSCEP); err != nil {
				m.status = err.Error()
			} else {
				m.autoSCEP = !m.autoSCEP
				m.status = "Auto SCEP Enroll " + onOff(m.autoSCEP)
			}
		}
	case editorScreen:
		switch key {
		case "ctrl+s":
			m.saveInventory()
		case "esc":
			if m.editor.Value() == m.initialJSON {
				m.screen, m.status = deviceScreen, ""
			} else {
				m.screen = discardScreen
			}
		default:
			return m.updateInput(msg)
		}
	case discardScreen:
		switch key {
		case "y":
			m.screen, m.status = deviceScreen, ""
		case "n", "esc":
			m.screen = editorScreen
		}
	case profilesScreen:
		switch key {
		case "esc", "backspace":
			m.screen, m.status = deviceScreen, ""
		case "up", "k":
			m.profileIndex = max(0, m.profileIndex-1)
		case "down", "j":
			m.profileIndex = moveDown(m.profileIndex, len(m.profiles))
		case "enter":
			m.openProfile()
		case "c":
			return m.startPoll()
		case "l":
			m.openViewer(diagnosticsScreen, m.diagnostics)
		}
	case profileScreen:
		switch key {
		case "esc":
			m.screen, m.status = profilesScreen, ""
		case "e":
			return m.startExport("profile.mobileconfig")
		case "s":
			if len(m.scepPayloads) > 0 {
				m.screen, m.status = scepScreen, ""
			}
		case "l":
			m.openViewer(diagnosticsScreen, m.diagnostics)
		default:
			return m.updateInput(msg)
		}
	case certificatesScreen:
		switch key {
		case "esc", "backspace":
			m.screen, m.status = deviceScreen, ""
		case "up", "k":
			m.certificateIndex = max(0, m.certificateIndex-1)
		case "down", "j":
			m.certificateIndex = moveDown(m.certificateIndex, len(m.certificates))
		case "enter":
			if len(m.certificates) > 0 {
				m.openCertificate()
			}
		}
	case certificateScreen:
		switch key {
		case "esc":
			m.screen, m.status = m.certificateBack, ""
		case "t":
			m.certificatePEM = !m.certificatePEM
			m.showCertificate()
		case "e":
			return m.startExport("certificate" + m.certificateExtension())
		default:
			return m.updateInput(msg)
		}
	case scepScreen:
		return m.handleSCEPKey(key)
	case confirmEnrollScreen:
		switch key {
		case "enter", "y":
			return m.startEnroll()
		case "esc", "n":
			m.screen, m.status = scepScreen, ""
		}
	case exportScreen:
		switch key {
		case "esc":
			m.screen, m.status = m.exportBack, ""
			m.exportPath.Blur()
		case "enter":
			if m.exportBack == certificateScreen {
				m.exportCertificate()
			} else {
				m.exportProfile()
			}
		default:
			return m.updateInput(msg)
		}
	case jamfPoliciesScreen:
		return m.jamfPoliciesKey(key)
	case confirmJamfScreen:
		switch key {
		case "enter":
			return m.startJamfPolicyRefresh()
		case "esc":
			m.screen, m.status = jamfPoliciesScreen, ""
		}
	case effectiveScreen, diagnosticsScreen, jamfPolicyScreen:
		if key == "esc" {
			if m.viewerBack == profileScreen {
				m.openProfile()
			} else {
				m.screen, m.status = m.viewerBack, ""
			}
		} else {
			return m.updateInput(msg)
		}
	}
	return nil
}

func (m *model) devicesKey(msg tea.KeyMsg) tea.Cmd {
	key := msg.String()
	if m.searching {
		switch key {
		case "esc":
			m.search.Reset()
			m.deviceIndex = 0
		case "enter":
		default:
			return m.updateInput(msg)
		}
		m.search.Blur()
		m.searching = false
		return nil
	}
	rows := m.filteredDevices()
	switch key {
	case "q", "esc":
		return tea.Quit
	case "/":
		m.searching = true
		return m.search.Focus()
	case "up", "k":
		m.deviceIndex = max(0, m.deviceIndex-1)
	case "down", "j":
		m.deviceIndex = moveDown(m.deviceIndex, len(rows))
	case "enter":
		if m.deviceIndex < len(rows) {
			m.status = ""
			m.openDevice(rows[m.deviceIndex].UDID)
		}
	case "n":
		d := device.New("", m.db)
		if err := d.Save(); err != nil {
			m.status = err.Error()
			return nil
		}
		m.search.Reset()
		m.status = "Device created"
		m.reloadDevices()
		m.openDevice(d.UDID)
		m.selectDevice(d.UDID)
	}
	return nil
}

func (m *model) selectDevice(id string) {
	rows := m.filteredDevices()
	m.deviceIndex = min(m.deviceIndex, max(0, len(rows)-1))
	for i, row := range rows {
		if row.UDID == id {
			m.deviceIndex = i
			return
		}
	}
}

func moveDown(index, count int) int {
	return min(index+1, max(0, count-1))
}

func (m *model) openEditor() tea.Cmd {
	inventory := m.selected.Inventory()
	if inventory.QueryResponses == nil {
		inventory.QueryResponses = map[string]any{}
	}
	raw, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		m.status = err.Error()
		return nil
	}
	m.editor.SetValue(string(raw))
	m.editor.SetCursor(0)
	m.initialJSON = m.editor.Value()
	m.screen, m.status = editorScreen, ""
	return m.editor.Focus()
}

func parseInventory(text string) (device.Inventory, error) {
	var inventory device.Inventory
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&inventory); err != nil {
		return device.Inventory{}, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return device.Inventory{}, errors.New("expected one JSON document")
	}
	for key, value := range inventory.QueryResponses {
		if value == nil {
			return device.Inventory{}, fmt.Errorf("QueryResponses.%s cannot be null", key)
		}
	}
	return inventory, nil
}

func (m *model) saveInventory() {
	inventory, err := parseInventory(m.editor.Value())
	if err == nil {
		err = m.selected.UpdateInventory(inventory)
	}
	if err != nil {
		m.status = "Inventory: " + err.Error()
		return
	}
	m.screen, m.status = deviceScreen, "Inventory saved"
	m.reloadDevices()
	m.selectDevice(m.deviceID)
}

func (m *model) showJSON(value any) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		m.status = err.Error()
		return
	}
	m.openViewer(effectiveScreen, string(raw))
}

func (m *model) openViewer(target screen, content string) {
	m.openStyledViewer(target, terminalText(content, true))
}

func (m *model) openStyledViewer(target screen, content string) {
	m.viewerBack = m.screen
	m.viewText = content
	m.viewer.SetContent(wrapViewerText(m.viewText, m.viewer.Width))
	m.viewer.GotoTop()
	m.screen, m.status = target, ""
}

func terminalText(s string, multiline bool) string {
	return strings.Map(func(r rune) rune {
		if multiline && (r == '\n' || r == '\t') {
			return r
		}
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, ansi.Strip(s))
}

type pollResult struct {
	err error
	log string
}

func (m *model) startPoll() tea.Cmd {
	if !enrolled(m.selected) {
		m.status = "Device is not enrolled"
		return nil
	}
	ctx, cancel := context.WithTimeout(m.ctx, time.Minute)
	m.cancelOperation = cancel
	m.busyLabel = "MDM poll"
	m.status = "Polling MDM… Esc cancels"
	id, db := m.deviceID, m.db
	return func() tea.Msg {
		m.operationLock.Lock()
		defer m.operationLock.Unlock()
		defer cancel()
		if err := ctx.Err(); err != nil {
			return pollResult{err: err}
		}
		d, err := device.Load(id, db)
		if err != nil {
			return pollResult{err: err}
		}
		client, err := d.MDMClient()
		if err != nil {
			return pollResult{err: err}
		}
		var output pollLog
		err = client.Connect(diagnostics.WithOutput(ctx, &output))
		return pollResult{err: err, log: output.String()}
	}
}

func (m *model) finishPoll(result pollResult) {
	m.cancelOperation = nil
	m.diagnostics = result.log
	m.status = "MDM queue processed"
	if result.err != nil {
		m.status = "MDM: " + result.err.Error()
		m.diagnostics += "\n" + m.status
	} else if result.log != "" {
		m.status = "MDM queue processed · l for diagnostics"
	}
	d, err := device.Load(m.deviceID, m.db)
	if err != nil {
		m.status += " · " + err.Error()
	} else {
		m.selected = d
	}
	var profileID string
	if m.profileIndex < len(m.profiles) {
		profileID = m.profiles[m.profileIndex].id
	}
	m.reloadProfiles(profileID)
	m.reloadCertificates("")
	m.reloadDevices()
}

type pollLog struct {
	bytes.Buffer
}

func (l *pollLog) Write(p []byte) (int, error) {
	// Keep only a bounded amount of diagnostics in memory.
	n := len(p)
	remaining := max(0, 32*1024-l.Len())
	l.Buffer.Write(p[:min(remaining, n)])
	return n, nil
}
