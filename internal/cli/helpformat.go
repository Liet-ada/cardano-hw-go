// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Help and usage texts as the argparse package for JavaScript (a port of
// Python 3.9's argparse, which cardano-hw-cli uses) writes them, quirks
// included: lengths are counted in UTF-16 code units, as JavaScript does,
// and the width follows the terminal.

// jsLen is the length of s as JavaScript counts it.
func jsLen(s string) int { return len(utf16.Encode([]rune(s))) }

// jsSlice cuts s at UTF-16 offsets, as String.prototype.slice does.
func jsSlice(s string, from, to int) string {
	u := utf16.Encode([]rune(s))
	from, to = max(0, min(from, len(u))), max(0, min(to, len(u)))
	if from >= to {
		return ""
	}
	return string(utf16.Decode(u[from:to]))
}

// jsRepr writes a string as Node's util.inspect does: in single quotes,
// or double quotes or backticks to avoid escaping a quote.
func jsRepr(s string) string {
	quote := byte('\'')
	if strings.Contains(s, "'") {
		switch {
		case !strings.Contains(s, `"`):
			quote = '"'
		case !strings.Contains(s, "`") && !strings.Contains(s, "${"):
			quote = '`'
		}
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\v':
			b.WriteString(`\v`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// jsNumber converts a string as JavaScript's unary plus does, for the
// forms an environment variable may take; NaN for others.
func jsNumber(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	switch strings.TrimLeft(s, "+-") {
	case "Infinity":
		if strings.HasPrefix(s, "-") {
			return math.Inf(-1)
		}
		return math.Inf(1)
	}
	if len(s) > 2 && s[0] == '0' {
		base := map[byte]int{'x': 16, 'X': 16, 'o': 8, 'O': 8, 'b': 2, 'B': 2}[s[1]]
		if base != 0 {
			n, err := strconv.ParseUint(s[2:], base, 64)
			if err != nil {
				return math.NaN()
			}
			return float64(n)
		}
	}
	if strings.ContainsAny(s, "xXpP_") || strings.HasPrefix(strings.TrimLeft(s, "+-"), "0x") {
		return math.NaN()
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}
	return f
}

// terminalColumns is argparse's get_terminal_size: COLUMNS when it is a
// number other than zero, else the width of the terminal on standard
// output, else 80.
func terminalColumns() float64 {
	if c := jsNumber(os.Getenv("COLUMNS")); c != 0 && !math.IsNaN(c) {
		return c
	}
	if c := stdoutColumns(); c > 0 {
		return float64(c)
	}
	return 80
}

// wrapText is the textwrap.wrap of the JavaScript argparse: it splits on
// whitespace only and breaks words longer than a line.
func wrapText(text string, width float64) []string {
	var chunks []string
	for _, f := range regexp.MustCompile(`[\t\n\v\f\r ]+|[^\t\n\v\f\r ]+`).FindAllString(text, -1) {
		chunks = append(chunks, f)
	}
	// reversed, so the next chunk is the last
	for i, j := 0, len(chunks)-1; i < j; i, j = i+1, j-1 {
		chunks[i], chunks[j] = chunks[j], chunks[i]
	}
	var lines []string
	blank := func(s string) bool { return strings.TrimSpace(s) == "" }
	for len(chunks) > 0 {
		var line []string
		curLen := 0
		if blank(chunks[len(chunks)-1]) && len(lines) > 0 {
			chunks = chunks[:len(chunks)-1]
		}
		for len(chunks) > 0 {
			l := jsLen(chunks[len(chunks)-1])
			if float64(curLen+l) > width {
				break
			}
			line = append(line, chunks[len(chunks)-1])
			chunks = chunks[:len(chunks)-1]
			curLen += l
		}
		if len(chunks) > 0 && float64(jsLen(chunks[len(chunks)-1])) > width {
			// a long word: cut it to fill the line (slice truncates)
			left := 1
			if width >= 1 {
				left = int(width - float64(curLen))
			}
			last := chunks[len(chunks)-1]
			line = append(line, jsSlice(last, 0, left))
			chunks[len(chunks)-1] = jsSlice(last, left, jsLen(last))
		}
		if len(line) > 0 && blank(line[len(line)-1]) {
			line = line[:len(line)-1]
		}
		lines = append(lines, strings.Join(line, ""))
	}
	return lines
}

var whitespaceRuns = regexp.MustCompile(`[ \t\n\r\f\v]+`)

// formatter builds a help text, as argparse's HelpFormatter.
type formatter struct {
	prog            string
	width           float64
	maxHelpPosition float64
	indent          int
	actionMaxLength int
}

func newFormatter(prog string) *formatter {
	width := terminalColumns() - 2
	return &formatter{prog: prog, width: width, maxHelpPosition: math.Min(24, math.Max(width-20, 4))}
}

// usageText is _format_usage, without the "usage: " prefix and the
// trailing blank line.
func (f *formatter) usageText(p *parser, prefix string) string {
	prog := f.prog
	var optionals, positionals []*action
	for _, a := range p.actions {
		if len(a.optionStrings) > 0 {
			optionals = append(optionals, a)
		} else {
			positionals = append(positionals, a)
		}
	}
	all := append(append([]*action{}, optionals...), positionals...)
	usage := prog + " " + f.actionsUsage(all, p.groups)
	if len(all) == 0 {
		usage = prog
	}
	textWidth := f.width - float64(f.indent)
	if float64(jsLen(prefix)+jsLen(usage)) <= textWidth {
		return usage
	}
	partRe := regexp.MustCompile(`\(.*?\)+(?:\s|$)|\[.*?\]+(?:\s|$)|\S+`)
	split := func(s string) []string {
		// the lookahead of the JavaScript regular expression, done by hand
		var parts []string
		for _, m := range partRe.FindAllString(s, -1) {
			parts = append(parts, strings.TrimRight(m, " \t\n\r\f\v"))
		}
		return parts
	}
	optParts := split(f.actionsUsage(optionals, p.groups))
	posParts := split(f.actionsUsage(positionals, p.groups))
	getLines := func(parts []string, indent string, withPrefix bool) []string {
		var lines []string
		var line []string
		lineLen := jsLen(indent) - 1
		if withPrefix {
			lineLen = jsLen(prefix) - 1
		}
		for _, part := range parts {
			// JavaScript's "&& line" is always true: an empty line may be
			// written, as cardano-hw-cli does
			if float64(lineLen+1+jsLen(part)) > textWidth {
				lines = append(lines, indent+strings.Join(line, " "))
				line = nil
				lineLen = jsLen(indent) - 1
			}
			line = append(line, part)
			lineLen += jsLen(part) + 1
		}
		if len(line) > 0 {
			lines = append(lines, indent+strings.Join(line, " "))
		}
		if withPrefix && len(lines) > 0 {
			lines[0] = jsSlice(lines[0], jsLen(indent), jsLen(lines[0]))
		}
		return lines
	}
	var lines []string
	if float64(jsLen(prefix)+jsLen(prog)) <= 0.75*textWidth {
		indent := strings.Repeat(" ", jsLen(prefix)+jsLen(prog)+1)
		switch {
		case len(optParts) > 0:
			lines = getLines(append([]string{prog}, optParts...), indent, true)
			lines = append(lines, getLines(posParts, indent, false)...)
		case len(posParts) > 0:
			lines = getLines(append([]string{prog}, posParts...), indent, true)
		default:
			lines = []string{prog}
		}
	} else {
		indent := strings.Repeat(" ", jsLen(prefix))
		parts := append(append([]string{}, optParts...), posParts...)
		lines = getLines(parts, indent, false)
		if len(lines) > 1 {
			lines = append(getLines(optParts, indent, false), getLines(posParts, indent, false)...)
		}
		lines = append([]string{prog}, lines...)
	}
	return strings.Join(lines, "\n")
}

// actionsUsage is _format_actions_usage.
func (f *formatter) actionsUsage(actions []*action, groups []*mutexGroup) string {
	inGroup := map[*action]bool{}
	inserts := map[int]string{}
	index := func(a *action) int {
		for i, x := range actions {
			if x == a {
				return i
			}
		}
		return -1
	}
	for _, g := range groups {
		if len(g.actions) == 0 {
			continue
		}
		start := index(g.actions[0])
		if start < 0 {
			continue
		}
		end := start + len(g.actions)
		if end > len(actions) {
			continue
		}
		same := true
		for i, a := range g.actions {
			if actions[start+i] != a {
				same = false
			}
		}
		if !same {
			continue
		}
		for _, a := range g.actions {
			inGroup[a] = true
		}
		open, closing := "[", "]"
		if g.required {
			open, closing = "(", ")"
		}
		if s, ok := inserts[start]; ok {
			inserts[start] = s + " " + open
		} else {
			inserts[start] = open
		}
		if s, ok := inserts[end]; ok {
			inserts[end] = s + closing
		} else {
			inserts[end] = closing
		}
		for i := start + 1; i < end; i++ {
			inserts[i] = "|"
		}
	}
	parts := make([]string, 0, len(actions))
	for _, a := range actions {
		var part string
		switch {
		case len(a.optionStrings) == 0:
			part = f.formatArgs(a)
			if inGroup[a] && strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
				part = part[1 : len(part)-1]
			}
		case a.nargs == nargsZero:
			part = a.optionStrings[0]
		default:
			part = a.optionStrings[0] + " " + f.formatArgs(a)
		}
		if len(a.optionStrings) > 0 && !a.required && !inGroup[a] {
			part = "[" + part + "]"
		}
		parts = append(parts, part)
	}
	// insert the group marks, from the end
	var at []int
	for i := range inserts {
		at = append(at, i)
	}
	for i := 0; i < len(at); i++ {
		for j := i + 1; j < len(at); j++ {
			if at[j] > at[i] {
				at[i], at[j] = at[j], at[i]
			}
		}
	}
	for _, i := range at {
		parts = append(parts[:i], append([]string{inserts[i]}, parts[i:]...)...)
	}
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	text := strings.Join(kept, " ")
	text = regexp.MustCompile(`([\[(]) `).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(` ([\])])`).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(`[\[(] *[\])]`).ReplaceAllString(text, "")
	text = regexp.MustCompile(`\(([^|]*)\)`).ReplaceAllString(text, "$1")
	return strings.TrimSpace(text)
}

// metavar is _metavar_formatter's result for one value.
func (a *action) metavarText() string {
	switch {
	case a.metavar != "":
		return a.metavar
	case a.nargs == nargsParser:
		return "{" + strings.Join(a.choices, ",") + "}"
	}
	return strings.ToUpper(a.dest)
}

func (f *formatter) formatArgs(a *action) string {
	switch a.nargs {
	case nargsOptional:
		return "[" + a.metavarText() + "]"
	case nargsParser:
		return a.metavarText() + " ..."
	case nargsZero:
		return ""
	}
	return a.metavarText()
}

func (f *formatter) invocation(a *action) string {
	if len(a.optionStrings) == 0 {
		return a.metavarText()
	}
	if a.nargs == nargsZero {
		return strings.Join(a.optionStrings, ", ")
	}
	args := f.formatArgs(a)
	parts := make([]string, len(a.optionStrings))
	for i, o := range a.optionStrings {
		parts[i] = o + " " + args
	}
	return strings.Join(parts, ", ")
}

// pad is the "%*s" and "%-*s" of argparse's formatting.
func pad(s string, n int, left bool) string {
	if n <= jsLen(s) {
		return s
	}
	if left {
		return s + strings.Repeat(" ", n-jsLen(s))
	}
	return strings.Repeat(" ", n-jsLen(s)) + s
}

func (f *formatter) formatAction(a *action) string {
	helpPosition := math.Min(float64(f.actionMaxLength+2), f.maxHelpPosition)
	helpWidth := math.Max(f.width-helpPosition, 11)
	actionWidth := int(helpPosition) - f.indent - 2
	header := f.invocation(a)
	var b strings.Builder
	indentFirst := 0
	switch {
	case a.help == "":
		b.WriteString(pad("", f.indent, false) + header + "\n")
	case jsLen(header) <= actionWidth:
		b.WriteString(pad("", f.indent, false) + pad(header, actionWidth, true) + "  ")
	default:
		b.WriteString(pad("", f.indent, false) + header + "\n")
		indentFirst = int(helpPosition)
	}
	if a.help != "" {
		text := strings.TrimSpace(whitespaceRuns.ReplaceAllString(a.help, " "))
		lines := wrapText(text, helpWidth)
		first := ""
		if len(lines) > 0 {
			first = lines[0]
		}
		b.WriteString(pad("", indentFirst, false) + first + "\n")
		for _, l := range lines[min(1, len(lines)):] {
			b.WriteString(pad("", int(helpPosition), false) + l + "\n")
		}
	}
	return b.String()
}

// help is format_help: usage, description, then the positional and the
// optional arguments.
func (f *formatter) help(p *parser) string {
	// the widest invocation decides where help texts start; it is measured
	// inside a section, indented by 2
	for _, a := range p.actions {
		f.actionMaxLength = max(f.actionMaxLength, jsLen(f.invocation(a))+2)
	}
	var b strings.Builder
	b.WriteString("usage: " + f.usageText(p, "usage: ") + "\n\n")
	if p.description != "" {
		text := strings.TrimSpace(whitespaceRuns.ReplaceAllString(p.description, " "))
		b.WriteString(strings.Join(wrapText(text, math.Max(f.width, 11)), "\n") + "\n\n")
	}
	section := func(title string, actions []*action) {
		f.indent = 2
		var items strings.Builder
		for _, a := range actions {
			items.WriteString(f.formatAction(a))
		}
		f.indent = 0
		if items.Len() == 0 {
			return
		}
		b.WriteString("\n" + title + ":\n" + items.String() + "\n")
	}
	var positionals, optionals []*action
	for _, a := range p.actions {
		if len(a.optionStrings) == 0 {
			positionals = append(positionals, a)
		} else {
			optionals = append(optionals, a)
		}
	}
	section("positional arguments", positionals)
	section("optional arguments", optionals)
	text := regexp.MustCompile(`\n\n\n+`).ReplaceAllString(b.String(), "\n\n")
	return strings.Trim(text, "\n")
}

// usageLine is format_usage, for errors.
func (f *formatter) usageLine(p *parser) string {
	return "usage: " + f.usageText(p, "usage: ")
}
