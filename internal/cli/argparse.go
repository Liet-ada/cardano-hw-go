// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Liet-ada/cardano-hw-go/internal/js"
)

// The command line follows cardano-hw-cli, which uses the argparse package
// for JavaScript, a port of Python 3.9's argparse. Its algorithm is
// reproduced here as far as cardano-hw-cli's commands use it: nested
// subcommands (every command, even one without subcommands, has a
// subcommand positional), long options with one value, an optional value
// or none, repeatable options, mutually exclusive groups and unambiguous
// prefixes of options. Values are checked as they are parsed, by the same
// checks cardano-hw-cli gives argparse as types, so the first error found
// is the same.

// option is an option as a command declares it.
type option struct {
	name     string // --tx-file
	dest     string
	metavar  string
	help     string
	required bool
	repeat   bool   // action append
	flag     bool   // action store_true
	optional bool   // nargs '?': the value may be left out
	constant string // value of an optional option given without one
	// conv is the type function of the option: it fails as
	// cardano-hw-cli's does on a bad value.
	conv func(string) error
}

type group struct {
	required bool
	options  []option
}

type command struct {
	name   string
	help   string
	subs   []*command
	opts   []option
	groups []group
}

// args are the parsed options of a command: the values of each destination
// in the order given.
type args struct {
	cmd    string // e.g. "transaction.witness"
	values map[string][]string
	flags  map[string]bool
	// given lists the options with a value in the order given.
	given []givenOption
}

type givenOption struct {
	name, value string
}

func (a *args) get(dest string) (string, bool) {
	v := a.values[dest]
	if len(v) == 0 {
		return "", false
	}
	return v[len(v)-1], true
}

func (a *args) all(dest string) []string { return a.values[dest] }

// usageError is an error in the command line itself; argparse prints the
// usage of the parser that found it and exits with 2.
type usageError struct {
	usage string
	msg   string
}

func (e *usageError) Error() string { return e.usage + "\n" + e.msg }

// helpRequest asks to print help and exit with 0.
type helpRequest struct{ text string }

func (h *helpRequest) Error() string { return h.text }

type nargsKind int

const (
	nargsOne nargsKind = iota
	nargsOptional
	nargsZero
	nargsParser
)

// action is an argparse action: an option, -h, or the subcommands.
type action struct {
	optionStrings []string
	dest          string
	metavar       string
	help          string
	required      bool
	nargs         nargsKind
	repeat        bool
	constant      string
	conv          func(string) error
	isHelp        bool
	// subcommands
	choices []string
	subs    map[string]*parser
}

type mutexGroup struct {
	required bool
	actions  []*action
}

// parser is an argparse ArgumentParser.
type parser struct {
	prog        string
	description string
	cmd         string // the command it sets, e.g. "transaction.witness"
	actions     []*action
	groups      []*mutexGroup
	options     map[string]*action
	optionOrder []string
}

func (p *parser) add(a *action) *action {
	p.actions = append(p.actions, a)
	for _, s := range a.optionStrings {
		p.options[s] = a
		p.optionOrder = append(p.optionOrder, s)
	}
	return a
}

func optionAction(o option) *action {
	a := &action{optionStrings: []string{o.name}, dest: o.dest, metavar: o.metavar, help: o.help,
		required: o.required, repeat: o.repeat, constant: o.constant, conv: o.conv}
	switch {
	case o.flag:
		a.nargs = nargsZero
	case o.optional:
		a.nargs = nargsOptional
	}
	return a
}

// newParser builds the parser of a command and its subcommands, as
// cardano-hw-cli's initParser does.
func newParser(c *command, prog, cmd string) *parser {
	p := &parser{prog: prog, description: c.help, cmd: cmd, options: map[string]*action{}}
	p.add(&action{optionStrings: []string{"-h", "--help"}, dest: "help", nargs: nargsZero, isHelp: true,
		help: "show this help message and exit"})
	subs := p.add(&action{nargs: nargsParser, choices: []string{}, subs: map[string]*parser{}})
	for _, s := range c.subs {
		sub := s.name
		if cmd != "" {
			sub = cmd + "." + s.name
		}
		subs.choices = append(subs.choices, s.name)
		subs.subs[s.name] = newParser(s, prog+" "+s.name, sub)
	}
	for _, g := range c.groups {
		mg := &mutexGroup{required: g.required}
		for _, o := range g.options {
			mg.actions = append(mg.actions, p.add(optionAction(o)))
		}
		p.groups = append(p.groups, mg)
	}
	for _, o := range c.opts {
		p.add(optionAction(o))
	}
	return p
}

func (p *parser) help() string { return newFormatter(p.prog).help(p) }

func (p *parser) fail(msg string) error {
	return &usageError{newFormatter(p.prog).usageLine(p), p.prog + ": error: " + msg}
}

// argumentError is argparse's ArgumentError: a message about an action.
type argumentError struct {
	action *action
	msg    string
}

func actionName(a *action) string {
	switch {
	case a == nil:
		return ""
	case len(a.optionStrings) > 0:
		return strings.Join(a.optionStrings, "/")
	case a.metavar != "":
		return a.metavar
	}
	return a.dest
}

func (e *argumentError) Error() string {
	if name := actionName(e.action); name != "" {
		return "argument " + name + ": " + e.msg
	}
	return e.msg
}

// optionTuple is what an argument string turns out to be: an option of the
// parser (or nil, an unknown one), as written, with a value after "=".
type optionTuple struct {
	action   *action
	option   string
	explicit *string
}

var negativeNumber = regexp.MustCompile(`^-\d+$|^-\d*\.\d+$`)

// parseOptional is _parse_optional: nil means a positional argument.
func (p *parser) parseOptional(arg string) (*optionTuple, error) {
	if arg == "" || arg[0] != '-' {
		return nil, nil
	}
	if a, ok := p.options[arg]; ok {
		return &optionTuple{a, arg, nil}, nil
	}
	if len(arg) == 1 {
		return nil, nil
	}
	if name, value, ok := strings.Cut(arg, "="); ok {
		if a, ok := p.options[name]; ok {
			return &optionTuple{a, name, &value}, nil
		}
	}
	tuples := p.optionTuples(arg)
	switch {
	case len(tuples) > 1:
		names := make([]string, len(tuples))
		for i, t := range tuples {
			names[i] = t.option
		}
		return nil, p.fail("ambiguous option: " + arg + " could match " + strings.Join(names, ", "))
	case len(tuples) == 1:
		return &tuples[0], nil
	}
	if negativeNumber.MatchString(arg) || strings.Contains(arg, " ") {
		return nil, nil
	}
	return &optionTuple{nil, arg, nil}, nil
}

// optionTuples is _get_option_tuples: the options an abbreviation may mean.
func (p *parser) optionTuples(arg string) []optionTuple {
	var out []optionTuple
	if arg[1] == '-' {
		prefix, value, hasValue := strings.Cut(arg, "=")
		var explicit *string
		if hasValue {
			explicit = &value
		}
		for _, s := range p.optionOrder {
			if strings.HasPrefix(s, prefix) {
				out = append(out, optionTuple{p.options[s], s, explicit})
			}
		}
		return out
	}
	short, rest := arg[:2], arg[2:]
	for _, s := range p.optionOrder {
		switch {
		case s == short:
			r := rest
			out = append(out, optionTuple{p.options[s], s, &r})
		case strings.HasPrefix(s, arg):
			out = append(out, optionTuple{p.options[s], s, nil})
		}
	}
	return out
}

// nargsPattern is _get_nargs_pattern, over the pattern of the arguments:
// O for an option, A for an argument, - for "--".
func nargsPattern(a *action) string {
	var pat string
	switch a.nargs {
	case nargsOne:
		pat = "(-*A-*)"
	case nargsOptional:
		pat = "(-*A?-*)"
	case nargsParser:
		pat = "(-*A[-AO]*)"
	case nargsZero:
		pat = "(-*-*)"
	}
	if len(a.optionStrings) > 0 {
		pat = strings.ReplaceAll(strings.ReplaceAll(pat, "-*", ""), "-", "")
	}
	return pat
}

func matchArgument(a *action, pattern string) (int, error) {
	m := regexp.MustCompile("^" + nargsPattern(a)).FindStringSubmatch(pattern)
	if m == nil {
		msg := "expected one argument"
		if a.nargs == nargsOptional {
			msg = "expected at most one argument"
		}
		return 0, &argumentError{a, msg}
	}
	return len(m[1]), nil
}

// namespace collects what a parser and its subparsers parse.
type namespace struct {
	args         *args
	unrecognized []string
}

// parseArgs is parse_args of the root parser.
func (p *parser) parseArgs(argv []string) (*args, error) {
	ns := &namespace{args: &args{values: map[string][]string{}, flags: map[string]bool{}}}
	extras, err := p.parseKnownArgs(argv, ns)
	if err != nil {
		return nil, err
	}
	if len(extras) > 0 {
		return nil, p.fail("unrecognized arguments: " + strings.Join(extras, " "))
	}
	return ns.args, nil
}

// parseKnownArgs is parse_known_args: argument errors are reported by this
// parser; errors of the type functions are not argument errors.
func (p *parser) parseKnownArgs(argv []string, ns *namespace) ([]string, error) {
	ns.args.cmd = p.cmd
	extras, err := p.parseKnown(argv, ns)
	if ae, ok := err.(*argumentError); ok {
		return nil, p.fail(ae.Error())
	}
	if err != nil {
		return nil, err
	}
	extras = append(extras, ns.unrecognized...)
	ns.unrecognized = nil
	return extras, nil
}

func (p *parser) parseKnown(argv []string, ns *namespace) ([]string, error) {
	conflicts := map[*action][]*action{}
	for _, g := range p.groups {
		for i, a := range g.actions {
			conflicts[a] = append(append(conflicts[a], g.actions[:i]...), g.actions[i+1:]...)
		}
	}
	tuples := map[int]*optionTuple{}
	var pattern strings.Builder
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--" {
			pattern.WriteString("-")
			pattern.WriteString(strings.Repeat("A", len(argv)-i-1))
			break
		}
		t, err := p.parseOptional(argv[i])
		if err != nil {
			return nil, err
		}
		if t == nil {
			pattern.WriteString("A")
		} else {
			tuples[i] = t
			pattern.WriteString("O")
		}
	}
	pat := pattern.String()

	seen := map[*action]bool{}
	seenNonDefault := map[*action]bool{}
	var extras []string

	takeAction := func(a *action, values []string, optionString string) error {
		seen[a] = true
		if a.nargs != nargsParser {
			for i, v := range values {
				if v == "--" {
					values = append(append([]string{}, values[:i]...), values[i+1:]...)
					break
				}
			}
		}
		// the type function converts what is given, or the constant of an
		// option given without its optional value
		if a.conv != nil && (len(values) > 0 || a.constant != "") && a.nargs != nargsZero {
			v := a.constant
			if len(values) > 0 {
				v = values[0]
			}
			if err := a.conv(v); err != nil {
				// argparse reports a TypeError of the type function as an
				// invalid value; the type functions are named "type"
				if js.IsTypeError(err) {
					return &argumentError{a, "invalid type value: " + jsRepr(v)}
				}
				return err
			}
		}
		if a.nargs == nargsParser && !contains(a.choices, values[0]) {
			quoted := make([]string, len(a.choices))
			for i, c := range a.choices {
				quoted[i] = jsRepr(c)
			}
			return &argumentError{a, "invalid choice: " + jsRepr(values[0]) + " (choose from " + strings.Join(quoted, ", ") + ")"}
		}
		// no default of cardano-hw-cli is the value an option gives
		seenNonDefault[a] = true
		for _, c := range conflicts[a] {
			if seenNonDefault[c] {
				return &argumentError{a, "not allowed with argument " + actionName(c)}
			}
		}
		switch {
		case a.isHelp:
			return &helpRequest{p.help()}
		case a.nargs == nargsParser:
			rest, err := a.subs[values[0]].parseKnownArgs(values[1:], ns)
			if err != nil {
				return err
			}
			ns.unrecognized = append(ns.unrecognized, rest...)
		case a.nargs == nargsZero:
			ns.args.flags[a.dest] = true
		default:
			v := a.constant
			if len(values) > 0 {
				v = values[0]
			}
			if a.repeat {
				ns.args.values[a.dest] = append(ns.args.values[a.dest], v)
			} else {
				ns.args.values[a.dest] = []string{v}
			}
			ns.args.given = append(ns.args.given, givenOption{optionString, v})
		}
		return nil
	}

	consumeOptional := func(start int) (int, error) {
		t := tuples[start]
		if t.action == nil {
			extras = append(extras, argv[start])
			return start + 1, nil
		}
		a, option, explicit := t.action, t.option, t.explicit
		type pending struct {
			a      *action
			values []string
			option string
		}
		var todo []pending
		var stop int
		for {
			if explicit == nil {
				from := start + 1
				n, err := matchArgument(a, pat[from:])
				if err != nil {
					return 0, err
				}
				stop = from + n
				todo = append(todo, pending{a, argv[from:stop], option})
				break
			}
			n, err := matchArgument(a, "A")
			if err != nil {
				return 0, err
			}
			if n == 0 && option[1] != '-' {
				// a short option without a value, then another one
				todo = append(todo, pending{a, nil, option})
				option = string(option[0]) + jsSlice(*explicit, 0, 1)
				next, ok := p.options[option]
				if !ok {
					return 0, &argumentError{a, "ignored explicit argument " + jsRepr(*explicit)}
				}
				rest := jsSlice(*explicit, 1, jsLen(*explicit))
				a, explicit = next, nil
				if rest != "" {
					explicit = &rest
				}
				continue
			}
			if n != 1 {
				return 0, &argumentError{a, "ignored explicit argument " + jsRepr(*explicit)}
			}
			stop = start + 1
			todo = append(todo, pending{a, []string{*explicit}, option})
			break
		}
		for _, t := range todo {
			if err := takeAction(t.a, t.values, t.option); err != nil {
				return 0, err
			}
		}
		return stop, nil
	}

	var positionals []*action
	for _, a := range p.actions {
		if len(a.optionStrings) == 0 {
			positionals = append(positionals, a)
		}
	}
	consumePositionals := func(start int) (int, error) {
		// as many positionals as match, from the start of what is left
		var counts []int
		for n := len(positionals); n > 0; n-- {
			re := "^"
			for _, a := range positionals[:n] {
				re += nargsPattern(a)
			}
			if m := regexp.MustCompile(re).FindStringSubmatch(pat[start:]); m != nil {
				for _, g := range m[1:] {
					counts = append(counts, len(g))
				}
				break
			}
		}
		for i, n := range counts {
			if err := takeAction(positionals[i], argv[start:start+n], ""); err != nil {
				return 0, err
			}
			start += n
		}
		positionals = positionals[len(counts):]
		return start, nil
	}

	indices := make([]int, 0, len(tuples))
	for i := range tuples {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	maxIndex := -1
	if len(indices) > 0 {
		maxIndex = indices[len(indices)-1]
	}
	start := 0
	for start <= maxIndex {
		next := maxIndex
		for _, i := range indices {
			if i >= start {
				next = i
				break
			}
		}
		if start != next {
			end, err := consumePositionals(start)
			if err != nil {
				return nil, err
			}
			if end > start {
				start = end
				continue
			}
		}
		if _, ok := tuples[start]; !ok {
			extras = append(extras, argv[start:next]...)
			start = next
		}
		var err error
		if start, err = consumeOptional(start); err != nil {
			return nil, err
		}
	}
	stop, err := consumePositionals(start)
	if err != nil {
		return nil, err
	}
	extras = append(extras, argv[stop:]...)

	var missing []string
	for _, a := range p.actions {
		if !seen[a] && a.required {
			missing = append(missing, actionName(a))
		}
	}
	if len(missing) > 0 {
		return nil, p.fail("the following arguments are required: " + strings.Join(missing, ", "))
	}
	for _, g := range p.groups {
		used := false
		for _, a := range g.actions {
			used = used || seenNonDefault[a]
		}
		if g.required && !used {
			names := make([]string, len(g.actions))
			for i, a := range g.actions {
				names[i] = actionName(a)
			}
			return nil, p.fail("one of the arguments " + strings.Join(names, " ") + " is required")
		}
	}
	return extras, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// parse parses argv (without the program name) against the command tree.
// An incomplete command parses as "", for which cardano-hw-cli prints its
// main help.
func parse(root *command, prog string, argv []string) (*args, error) {
	if len(argv) > 0 && argv[0] == "shelley" {
		argv = argv[1:]
	}
	a, err := newParser(root, prog, "").parseArgs(argv)
	if err != nil {
		return nil, err
	}
	if c := find(root, a.cmd); c == nil || len(c.subs) > 0 {
		a.cmd = ""
	}
	return a, nil
}

func find(c *command, cmd string) *command {
	if cmd == "" {
		return c
	}
	for _, name := range strings.Split(cmd, ".") {
		var next *command
		for _, s := range c.subs {
			if s.name == name {
				next = s
			}
		}
		if next == nil {
			return nil
		}
		c = next
	}
	return c
}

// help is the help of the root command.
func help(root *command, prog string, _ []string) string {
	return newParser(root, prog, "").help()
}

// sortedKeys is used by tests.
func sortedKeys(m map[string][]string) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
