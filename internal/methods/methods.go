// Package methods holds the fast in-VM file methods for an already-running
// wrap.
//
// Selectors match omp/pi: `file`, `file:5`, `file:5-10`, `file:5:2`.
package methods

import (
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/nalajala4naresh/box/internal/sandbox"
	"github.com/nalajala4naresh/box/internal/shell"
)

// Workspace is the guest path of the bound project.
const Workspace = "/home/user/workspace"

// LineKind selects lines of a file.
type LineKind int

const (
	All LineKind = iota
	From
	Range
	Count
)

// LineSpec is a parsed line selector.
type LineSpec struct {
	Kind  LineKind
	Start int
	End   int
	Count int
}

// Selector is a guest path plus a line selection.
type Selector struct {
	Path  string
	Lines LineSpec
}

// Kind names a method.
type Kind int

const (
	Ls Kind = iota
	Grep
	Read
	Write
	Bash
	Find
)

// Method is one parsed method call.
type Method struct {
	Kind     Kind
	Args     []string
	Pattern  string
	Selector Selector
	Path     string
	// Content is nil when the write content comes from stdin.
	Content *string
	Script  string
}

// Parse recognizes a method invocation, or returns false.
func Parse(command []string) (Method, bool) {
	if len(command) == 0 {
		return Method{}, false
	}
	name, rest := command[0], command[1:]
	switch name {
	case "ls":
		return Method{Kind: Ls, Args: rest}, true
	case "grep":
		if len(rest) == 0 {
			return Method{}, false
		}
		return Method{Kind: Grep, Pattern: rest[0], Args: rest[1:]}, true
	case "read":
		if len(rest) == 0 {
			return Method{}, false
		}
		return Method{Kind: Read, Selector: ParseSelector(rest[0])}, true
	case "write":
		if len(rest) == 0 {
			return Method{}, false
		}
		m := Method{Kind: Write, Path: GuestPath(rest[0])}
		if len(rest) > 1 {
			content := strings.Join(rest[1:], " ")
			m.Content = &content
		}
		return m, true
	case "bash":
		if len(rest) == 0 {
			return Method{}, false
		}
		return Method{Kind: Bash, Script: strings.Join(rest, " ")}, true
	case "find":
		return Method{Kind: Find, Args: rest}, true
	}
	return Method{}, false
}

// ParseSelector parses `file`, `file:5`, `file:5-10`, or `file:5:2`.
func ParseSelector(raw string) Selector {
	if p, start, count, ok := splitCount(raw); ok {
		return Selector{Path: GuestPath(p), Lines: LineSpec{Kind: Count, Start: start, Count: count}}
	}
	if p, start, end, ok := splitRange(raw); ok {
		return Selector{Path: GuestPath(p), Lines: LineSpec{Kind: Range, Start: start, End: end}}
	}
	if p, start, ok := splitFrom(raw); ok {
		return Selector{Path: GuestPath(p), Lines: LineSpec{Kind: From, Start: start}}
	}
	return Selector{Path: GuestPath(raw), Lines: LineSpec{Kind: All}}
}

func rsplitOnce(s, sep string) (string, string, bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

func splitCount(raw string) (string, int, int, bool) {
	left, countRaw, ok := rsplitOnce(raw, ":")
	if !ok {
		return "", 0, 0, false
	}
	count, ok := parseLine(countRaw)
	if !ok {
		return "", 0, 0, false
	}
	p, startRaw, ok := rsplitOnce(left, ":")
	if !ok {
		return "", 0, 0, false
	}
	start, ok := parseLine(startRaw)
	if !ok || p == "" {
		return "", 0, 0, false
	}
	return p, start, count, true
}

func splitRange(raw string) (string, int, int, bool) {
	p, span, ok := rsplitOnce(raw, ":")
	if !ok {
		return "", 0, 0, false
	}
	startRaw, endRaw, ok := strings.Cut(span, "-")
	if !ok {
		return "", 0, 0, false
	}
	start, ok1 := parseLine(startRaw)
	end, ok2 := parseLine(endRaw)
	if !ok1 || !ok2 || p == "" || start > end {
		return "", 0, 0, false
	}
	return p, start, end, true
}

func splitFrom(raw string) (string, int, bool) {
	p, startRaw, ok := rsplitOnce(raw, ":")
	if !ok {
		return "", 0, false
	}
	start, ok := parseLine(startRaw)
	if !ok || p == "" {
		return "", 0, false
	}
	return p, start, true
}

func parseLine(raw string) (int, bool) {
	if raw == "" || strings.TrimLeft(raw, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	return n, err == nil && n >= 1
}

// GuestPath resolves a method path: relative paths are under the workspace.
func GuestPath(raw string) string {
	if raw == "" || raw == "." {
		return Workspace
	}
	if strings.HasPrefix(raw, "/") {
		return raw
	}
	return Workspace + "/" + raw
}

// Run executes a method against a running sandbox.
func Run(sb *sandbox.Sandbox, m Method, pathExports string) (int, error) {
	switch m.Kind {
	case Ls:
		return execSh(sb, lsScript(m.Args))
	case Grep:
		return execSh(sb, grepScript(m.Pattern, m.Args))
	case Read:
		return execSh(sb, ReadScript(m.Selector))
	case Write:
		return writeGuest(sb, m.Path, m.Content)
	case Bash:
		return execSh(sb, pathExports+"; "+m.Script)
	case Find:
		return execSh(sb, findScript(m.Args))
	}
	return 2, fmt.Errorf("unknown method")
}

func lsScript(args []string) string {
	if len(args) == 0 {
		return "ls -la -- " + shell.Quote(Workspace)
	}
	allFlags := true
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			allFlags = false
			break
		}
	}
	if allFlags {
		return fmt.Sprintf("ls %s -- %s", shell.Join(args), shell.Quote(Workspace))
	}
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			out = append(out, a)
		} else {
			out = append(out, GuestPath(a))
		}
	}
	return "ls -la -- " + shell.Join(out)
}

func grepScript(pattern string, args []string) string {
	p := Workspace
	if len(args) > 0 {
		p = GuestPath(args[0])
	}
	extra := ""
	if len(args) > 1 {
		extra = " " + shell.Join(args[1:])
	}
	return fmt.Sprintf("grep -n -R -- %s %s%s", shell.Quote(pattern), shell.Quote(p), extra)
}

// ReadScript prints the selected lines.
func ReadScript(sel Selector) string {
	p := shell.Quote(sel.Path)
	switch sel.Lines.Kind {
	case From:
		return fmt.Sprintf("tail -n +%d -- %s", sel.Lines.Start, p)
	case Range:
		return fmt.Sprintf("sed -n '%d,%dp' -- %s", sel.Lines.Start, sel.Lines.End, p)
	case Count:
		end := sel.Lines.Start + max(sel.Lines.Count-1, 0)
		return fmt.Sprintf("sed -n '%d,%dp' -- %s", sel.Lines.Start, end, p)
	}
	return "cat -- " + p
}

func findScript(args []string) string {
	if len(args) == 0 {
		return "find " + shell.Quote(Workspace)
	}
	if strings.HasPrefix(args[0], "-") {
		return fmt.Sprintf("find %s %s", shell.Quote(Workspace), shell.Join(args))
	}
	p := GuestPath(args[0])
	if len(args) == 1 {
		return "find " + shell.Quote(p)
	}
	return fmt.Sprintf("find %s %s", shell.Quote(p), shell.Join(args[1:]))
}

func execSh(sb *sandbox.Sandbox, script string) (int, error) {
	out, err := sb.Exec(sandbox.ExecOptions{
		Argv:    []string{"/bin/sh", "-c", script},
		Cwd:     Workspace,
		Timeout: 30 * time.Second,
	})
	os.Stdout.Write(out.Stdout)
	os.Stderr.Write(out.Stderr)
	if err != nil {
		return 1, fmt.Errorf("wrap method: %w", err)
	}
	return out.Code, nil
}

func writeGuest(sb *sandbox.Sandbox, guest string, content *string) (int, error) {
	var data []byte
	if content != nil {
		data = []byte(*content)
	} else {
		var err error
		if data, err = io.ReadAll(os.Stdin); err != nil {
			return 1, fmt.Errorf("read stdin for wrap write: %w", err)
		}
	}
	if parent := path.Dir(guest); parent != "" && parent != "." {
		if err := sb.Mkdir(parent, sb.Spec.User); err != nil {
			return 1, fmt.Errorf("create wrap write parent: %w", err)
		}
	}
	if err := sb.WriteFile(guest, data, 0o644, sb.Spec.User); err != nil {
		return 1, fmt.Errorf("wrap write: %w", err)
	}
	return 0, nil
}
