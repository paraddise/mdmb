package tui

import (
	"encoding/xml"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	markupStyle  = lipgloss.NewStyle().TabWidth(-1).Foreground(lipgloss.AdaptiveColor{Light: "#60409B", Dark: "#C4ACFF"})
	valueStyle   = lipgloss.NewStyle().TabWidth(-1).Foreground(lipgloss.AdaptiveColor{Light: "#256236", Dark: "#9BD8A7"})
	xmlKeyStyle  = titleStyle.TabWidth(-1)
	viewerStyles = regexp.MustCompile("\x1b\\[[0-9;:]*m|\n")
)

func highlightXML(source string) string {
	decoder := xml.NewDecoder(strings.NewReader(source))
	var out strings.Builder
	var element string
	for {
		start := decoder.InputOffset()
		token, err := decoder.RawToken()
		if err != nil {
			out.WriteString(terminalText(source[start:], true))
			return out.String()
		}
		raw := terminalText(source[start:decoder.InputOffset()], true)
		switch token := token.(type) {
		case xml.StartElement:
			element = token.Name.Local
			raw = markupStyle.Render(raw)
		case xml.EndElement:
			element = ""
			if raw != "" {
				raw = markupStyle.Render(raw)
			}
		case xml.ProcInst, xml.Directive, xml.Comment:
			raw = mutedStyle.TabWidth(-1).Render(raw)
		case xml.CharData:
			if strings.TrimSpace(raw) != "" {
				if element == "key" {
					raw = xmlKeyStyle.Render(raw)
				} else {
					raw = valueStyle.Render(raw)
				}
			}
		}
		out.WriteString(raw)
	}
}

func wrapViewerText(content string, width int) string {
	wrapped := ansi.Hardwrap(content, width, true)
	if !strings.Contains(wrapped, "\x1b") {
		return wrapped
	}
	// The viewport can start at any line, so reopen an active style after wrapping.
	var style string
	return viewerStyles.ReplaceAllStringFunc(wrapped, func(token string) string {
		switch token {
		case ansi.ResetStyle, "\x1b[0m":
			style = ""
		case "\n":
			if style != "" {
				return ansi.ResetStyle + "\n" + style
			}
		default:
			style = token
		}
		return token
	})
}
