package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

func TestXMLHighlightingPreservesSource(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })

	input := "<?xml version=\"1.0\"?>\n<dict>\n\t<key>Name</key>\n\t<string>A &amp; B</string>\n\t<true/>\n</dict>"
	got := highlightXML(input)
	if ansi.Strip(got) != input {
		t.Fatal("highlighting changed the displayed XML")
	}
	for _, token := range []string{
		mutedStyle.Render("<?xml version=\"1.0\"?>"),
		markupStyle.Render("<true/>"),
		xmlKeyStyle.Render("Name"),
		valueStyle.Render("A &amp; B"),
	} {
		if token == ansi.Strip(token) || !strings.Contains(got, token) {
			t.Fatalf("missing highlighted token: %q", token)
		}
	}
}

func TestViewerWrappingRestoresStyleOnEachLine(t *testing.T) {
	green := "\x1b[32m"
	lines := strings.Split(wrapViewerText(green+"abcdef\x1b[0m\nplain", 3), "\n")
	if len(lines) != 4 ||
		lines[0] != green+"abc"+ansi.ResetStyle ||
		lines[1] != green+"def\x1b[0m" ||
		lines[2] != "pla" || lines[3] != "in" {
		t.Fatalf("unexpected wrapped lines: %q", lines)
	}
}
