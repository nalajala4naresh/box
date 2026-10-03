// Package ui is wrap's pre-entry surface.
//
// Thesis: calibrated, threshold, quiet; never dashboard-like.
// Signature: a layer rail that fills as snapshots land, then collapses into
// one host → vm crossing.
//
// Primary: current layer or the crossing.
// Supporting: completed marks, session kind.
// Ambient: missing secrets, leftover sandboxes.
//
// Scrollback CLI + one bounded five-line live region during setup. Never
// alternate screen.
package ui

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	primaryHex = 0xeceff1 // porcelain
	mutedHex   = 0x78909c // slate
	accentHex  = 0x4fc3f7 // cyan
	vmHex      = 0xc4a7e7 // lavender identity
	okHex      = 0x81c784 // sage
	warnHex    = 0xf78c6c // coral warning
	dangerHex  = 0xef5350 // red danger
)

var spinner = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

const (
	spinDelay    = 150 * time.Millisecond
	spinEvery    = 90 * time.Millisecond
	historyCap   = 48
	liveTailRows = 4
	liveRows     = liveTailRows + 1
	minWidth     = 20
	defaultWidth = 80

	hideCursor   = "\x1b[?25l"
	showCursor   = "\x1b[?25h"
	reset        = "\x1b[0m"
	clearLine    = "\r\x1b[2K"
	cursorUpLive = "\x1b[4A"
	cursorDown   = "\x1b[1B"
)

// SpinPeriod is how often callers should Tick a live region.
func SpinPeriod() time.Duration { return spinEvery }

// Theme paints text with wrap's palette when color is enabled.
type Theme struct {
	Color bool
}

// DetectTheme enables color for a terminal stderr unless the environment
// says otherwise.
func DetectTheme() Theme { return Theme{Color: ColorEnabled()} }

// Paint wraps text in a 24-bit foreground color.
func (t Theme) Paint(hex uint32, text string) string {
	if !t.Color || text == "" {
		return text
	}
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s%s", (hex>>16)&0xff, (hex>>8)&0xff, hex&0xff, text, reset)
}

func (t Theme) Primary(text string) string { return t.Paint(primaryHex, text) }
func (t Theme) Muted(text string) string   { return t.Paint(mutedHex, text) }
func (t Theme) Accent(text string) string  { return t.Paint(accentHex, text) }
func (t Theme) VM(text string) string      { return t.Paint(vmHex, text) }
func (t Theme) OK(text string) string      { return t.Paint(okHex, text) }
func (t Theme) Warn(text string) string    { return t.Paint(warnHex, text) }
func (t Theme) Danger(text string) string  { return t.Paint(dangerHex, text) }

// CrossingKind says how the session VM was obtained.
type CrossingKind int

const (
	New CrossingKind = iota
	Reused
	Reset
)

func (k CrossingKind) label() string {
	switch k {
	case Reused:
		return "reused"
	case Reset:
		return "reset"
	}
	return "new"
}

// LayerEnd says how a build layer finished.
type LayerEnd int

const (
	LayerReused LayerEnd = iota
	LayerSnapped
)

// UI writes the pre-entry surface to stderr.
type UI struct {
	theme       Theme
	interactive bool
	out         io.Writer
}

// Stderr is the UI on the process's stderr.
func Stderr() *UI {
	return &UI{theme: DetectTheme(), interactive: term.IsTerminal(int(os.Stderr.Fd())), out: os.Stderr}
}

func (u *UI) line(text string) { fmt.Fprintln(u.out, text) }

func (u *UI) SettingUpBase() {
	u.hideCursor()
	u.line(FormatSetup(u.theme, "base"))
}

func (u *UI) SettingUpProject() {
	u.hideCursor()
	u.line(FormatSetup(u.theme, "project"))
}

func (u *UI) hideCursor() {
	if u.interactive {
		fmt.Fprint(u.out, hideCursor)
	}
}

func (u *UI) Rebuild(layers int) { u.line(FormatRebuild(u.theme, layers)) }

func (u *UI) LayerReused(id string) { u.line(FormatLayerEnd(u.theme, id, LayerReused)) }

func (u *UI) StartLayer(id string) *Live { return u.StartTask(id) }

func (u *UI) StartTask(id string) *Live { return newLive(u.theme, u.interactive, u.out, id) }

func (u *UI) Leftover(name string, err error) {
	u.line(FormatLeftover(u.theme, name, err.Error()))
}

func (u *UI) Crossing(host, workspace string, kind CrossingKind, cpus uint8, memoryMiB, memoryMaxMiB uint32) {
	u.line(FormatCrossing(u.theme, StderrWidth(), host, workspace, kind, cpus, memoryMiB, memoryMaxMiB))
}

func (u *UI) Exposures(report ExposureReport) {
	u.line(FormatExposures(u.theme, report))
}

func (u *UI) Attached() { u.line("  " + u.theme.OK("fully attached")) }

func (u *UI) StopFailed(err error) { u.line(FormatStopFailed(u.theme, err.Error())) }

func (u *UI) Warn(msg string) { u.line(u.theme.Warn("warning: " + msg)) }

func (u *UI) Fatal(err error) {
	RestoreTerminal()
	u.line(FormatFatal(u.theme, err.Error()))
}

// Live is the bounded live region for one layer or task.
type Live struct {
	mu           sync.Mutex
	theme        Theme
	interactive  bool
	out          io.Writer
	layer        string
	phase        string
	spinnerI     int
	started      time.Time
	lastDraw     time.Time
	lines        *LineBuf
	carry        []byte
	cursorHidden bool
	finished     bool
	rendered     bool
}

func newLive(theme Theme, interactive bool, out io.Writer, id string) *Live {
	now := time.Now()
	return &Live{theme: theme, interactive: interactive, out: out, layer: Sanitize(id),
		started: now, lastDraw: now, lines: NewLineBuf()}
}

func (l *Live) FeedStdout(chunk []byte) { l.feed(chunk, os.Stdout) }

func (l *Live) FeedStderr(chunk []byte) { l.feed(chunk, os.Stderr) }

func (l *Live) feed(chunk []byte, passthrough *os.File) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.interactive {
		passthrough.Write(chunk)
		return
	}
	l.carry = append(l.carry, chunk...)
	valid := validUTF8Prefix(l.carry)
	if valid == 0 {
		return
	}
	text := string(l.carry[:valid])
	l.carry = append(l.carry[:0], l.carry[valid:]...)
	l.lines.Push(text)
	l.draw(false)
}

// validUTF8Prefix is how many leading bytes form complete UTF-8, leaving a
// split trailing rune for the next chunk.
func validUTF8Prefix(b []byte) int {
	if utf8.Valid(b) {
		return len(b)
	}
	for cut := len(b) - 1; cut >= 0 && cut >= len(b)-utf8.UTFMax; cut-- {
		if utf8.Valid(b[:cut]) {
			return cut
		}
	}
	// Invalid bytes mid-stream: pass everything through lossily.
	return len(b)
}

func (l *Live) Tick() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.interactive || l.finished || time.Since(l.lastDraw) < spinEvery {
		return
	}
	if time.Since(l.started) >= spinDelay {
		l.spinnerI++
	}
	l.draw(true)
}

func (l *Live) Phase(phase string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.phase = phase
	l.draw(true)
}

func (l *Live) Succeed() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finished {
		return
	}
	l.clearLive()
	fmt.Fprintln(l.out, FormatLayerEnd(l.theme, l.layer, LayerSnapped))
	l.finish()
}

func (l *Live) Done() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finished {
		return
	}
	l.clearLive()
	l.finish()
}

func (l *Live) Fail(detail string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finished {
		return
	}
	l.clearLive()
	fmt.Fprintln(l.out, FormatLayerFail(l.theme, l.layer, detail))
	for _, line := range l.lines.History() {
		fmt.Fprintln(l.out, "    "+l.theme.Muted(line))
	}
	l.finish()
}

func (l *Live) Interrupt() { l.Fail("interrupted") }

// Close clears an unfinished region, like Rust's Drop.
func (l *Live) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.finished {
		l.clearLive()
	}
	l.showCursor()
}

func (l *Live) draw(force bool) {
	if !l.interactive || l.finished {
		return
	}
	spinning := time.Since(l.started) >= spinDelay
	if !force && !spinning && l.phase == "" && l.lines.Snippet() == "" {
		return
	}
	if spinning && !l.cursorHidden {
		fmt.Fprint(l.out, hideCursor)
		l.cursorHidden = true
	}
	spin := ' '
	if spinning {
		spin = spinner[l.spinnerI%len(spinner)]
	}
	region := formatLiveRegion(l.theme, StderrWidth(), l.layer, spin, l.phase, l.lines)
	var frame strings.Builder
	if l.rendered {
		frame.WriteString("\r" + cursorUpLive)
	}
	for index, line := range strings.Split(region, "\n") {
		frame.WriteString(clearLine + line)
		if index+1 < liveRows {
			if l.rendered {
				frame.WriteString(cursorDown)
			} else {
				frame.WriteString("\n")
			}
		}
	}
	fmt.Fprint(l.out, frame.String())
	l.rendered = true
	l.lastDraw = time.Now()
}

func (l *Live) clearLive() {
	if !l.interactive || !l.rendered {
		return
	}
	var frame strings.Builder
	frame.WriteString("\r" + cursorUpLive)
	for row := 0; row < liveRows; row++ {
		frame.WriteString("\x1b[2K")
		if row+1 < liveRows {
			frame.WriteString(cursorDown)
		}
	}
	frame.WriteString("\r" + cursorUpLive)
	fmt.Fprint(l.out, frame.String())
	l.rendered = false
}

func (l *Live) finish() {
	l.finished = true
	l.showCursor()
}

func (l *Live) showCursor() {
	if l.cursorHidden {
		RestoreTerminal()
		l.cursorHidden = false
	}
}

// LineBuf keeps the partial line and a bounded history of committed lines.
type LineBuf struct {
	partial []rune
	history []string
}

func NewLineBuf() *LineBuf { return &LineBuf{} }

func (b *LineBuf) Push(text string) {
	for _, ch := range text {
		switch {
		case ch == '\n':
			b.commit()
		case ch == '\r':
			b.partial = b.partial[:0]
		case isControl(ch) && ch != '\x1b':
		default:
			b.partial = append(b.partial, ch)
		}
	}
}

func (b *LineBuf) commit() {
	line := Sanitize(string(b.partial))
	b.partial = b.partial[:0]
	if line == "" {
		return
	}
	if len(b.history) == historyCap {
		b.history = b.history[1:]
	}
	b.history = append(b.history, line)
}

func (b *LineBuf) Snippet() string {
	if current := Sanitize(string(b.partial)); current != "" {
		return current
	}
	if len(b.history) == 0 {
		return ""
	}
	return b.history[len(b.history)-1]
}

func (b *LineBuf) History() []string { return b.history }

// FormatCrossing renders the host → vm line, dropping detail to fit width.
func FormatCrossing(theme Theme, width int, host, workspace string, kind CrossingKind, cpus uint8, memoryMiB, memoryMaxMiB uint32) string {
	host = Sanitize(host)
	workspace = Sanitize(workspace)
	kindLabel := kind.label()
	resources := formatResources(cpus, memoryMiB, memoryMaxMiB)
	width = max(width, minWidth)

	baseWidth := func(h, w string) int { return DisplayWidth(h) + 6 + DisplayWidth(w) }
	suffixWidth := func(text string) int { return 5 + DisplayWidth(text) }
	base := baseWidth(host, workspace)
	if base <= width {
		withKind := base + suffixWidth(kindLabel)
		withResources := base + suffixWidth(resources)
		switch {
		case withKind+suffixWidth(resources) <= width:
			return renderCrossing(theme, host, workspace, kindLabel, resources)
		case withResources <= width:
			return renderCrossing(theme, host, workspace, "", resources)
		case withKind <= width:
			return renderCrossing(theme, host, workspace, kindLabel, "")
		}
		return renderCrossing(theme, host, workspace, "", "")
	}
	budget := max(width-max(baseWidth("", ""), 6), 0)
	hostBudget := max(budget/3, 2)
	workspaceBudget := max(budget-hostBudget, 2)
	return renderCrossing(theme, TruncateCells(host, hostBudget), TruncateCells(workspace, workspaceBudget), "", "")
}

func renderCrossing(theme Theme, host, workspace, kind, resources string) string {
	line := fmt.Sprintf("%s %s %s%s", theme.Accent(host), theme.Muted("→"), theme.VM("vm:"), theme.Primary(workspace))
	if kind != "" {
		line += fmt.Sprintf("  %s  %s", theme.Muted("·"), theme.Muted(kind))
	}
	if resources != "" {
		line += fmt.Sprintf("  %s  %s", theme.Muted("·"), theme.Primary(resources))
	}
	return line
}

func formatResources(cpus uint8, memoryMiB, memoryMaxMiB uint32) string {
	var memory string
	switch {
	case memoryMiB == memoryMaxMiB:
		memory = formatMemory(memoryMiB)
	case memoryMiB%1024 == 0 && memoryMaxMiB%1024 == 0:
		memory = fmt.Sprintf("%d–%d GiB", memoryMiB/1024, memoryMaxMiB/1024)
	default:
		memory = fmt.Sprintf("%d–%d MiB", memoryMiB, memoryMaxMiB)
	}
	return fmt.Sprintf("%d CPU · %s", cpus, memory)
}

func formatMemory(memoryMiB uint32) string {
	if memoryMiB%1024 == 0 {
		return fmt.Sprintf("%d GiB", memoryMiB/1024)
	}
	return fmt.Sprintf("%d MiB", memoryMiB)
}

func FormatLayerEnd(theme Theme, id string, end LayerEnd) string {
	id = Sanitize(id)
	if end == LayerReused {
		return fmt.Sprintf("  %s  %s", theme.Muted("·"), theme.Muted(id))
	}
	return fmt.Sprintf("  %s  %s", theme.OK("●"), theme.Primary(id))
}

func FormatLayerFail(theme Theme, id, detail string) string {
	return fmt.Sprintf("  %s  %s  %s  %s", theme.Danger("×"), theme.Primary(Sanitize(id)), theme.Muted("·"), theme.Danger(Sanitize(detail)))
}

func FormatLiveLine(theme Theme, width int, id string, spin rune, phase string) string {
	id = Sanitize(id)
	phase = Sanitize(phase)
	width = max(width, minWidth)
	mark := theme.VM(string(spin))
	if spin == ' ' {
		mark = theme.Muted(string(spin))
	}
	prefixW := DisplayWidth(fmt.Sprintf("  %c %s", spin, id))
	if prefixW >= width {
		return fmt.Sprintf("  %s %s", mark, theme.Primary(TruncateCells(id, max(width-4, 0))))
	}
	if phase == "" {
		return fmt.Sprintf("  %s %s", mark, theme.Primary(id))
	}
	room := max(width-(prefixW+2), 0)
	if room < 2 {
		return fmt.Sprintf("  %s %s", mark, theme.Primary(id))
	}
	return fmt.Sprintf("  %s %s  %s", mark, theme.Primary(id), theme.Muted(TruncateCells(phase, room)))
}

func formatLiveRegion(theme Theme, width int, id string, spin rune, phase string, lines *LineBuf) string {
	out := FormatLiveLine(theme, width, id, spin, phase)
	partial := Sanitize(string(lines.partial))
	historyLimit := liveTailRows
	if partial != "" {
		historyLimit--
	}
	start := max(len(lines.history)-historyLimit, 0)
	tailRows := 0
	for _, line := range lines.history[start:] {
		out += "\n" + formatLiveTail(theme, width, line)
		tailRows++
	}
	if partial != "" {
		out += "\n" + formatLiveTail(theme, width, partial)
		tailRows++
	}
	for ; tailRows < liveTailRows; tailRows++ {
		out += "\n"
	}
	return out
}

func formatLiveTail(theme Theme, width int, line string) string {
	return "    " + theme.Muted(TruncateCells(line, max(max(width, minWidth)-4, 0)))
}

func FormatSetup(theme Theme, target string) string {
	return theme.Primary(fmt.Sprintf("setting up %s vm", Sanitize(target)))
}

func FormatRebuild(theme Theme, layers int) string {
	return fmt.Sprintf("  %s  %s", theme.Warn("rebuild"), theme.Muted(fmt.Sprintf("%d layers", layers)))
}

func FormatLeftover(theme Theme, name, err string) string {
	return fmt.Sprintf("  %s  %s  %s  %s", theme.Muted("leftover"), theme.Primary(Sanitize(name)), theme.Muted("·"), theme.Muted(Sanitize(err)))
}

func FormatStopFailed(theme Theme, err string) string {
	return fmt.Sprintf("  %s  %s  %s", theme.Danger("stop failed"), theme.Muted("·"), theme.Muted(Sanitize(err)))
}

func FormatFatal(theme Theme, err string) string {
	// Sanitize per line so multi-line errors (console tails, hints) keep
	// their shape; control characters inside a line are still stripped.
	lines := strings.Split(err, "\n")
	for i, line := range lines {
		lines[i] = Sanitize(line)
	}
	return fmt.Sprintf("%s  %s", theme.Danger("wrap"), theme.Primary(strings.Join(lines, "\n")))
}

// ColorEnabled honors NO_COLOR, CLICOLOR=0, and CLICOLOR_FORCE=1, then falls
// back to whether stderr is a terminal.
func ColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("CLICOLOR") == "0" {
		return false
	}
	if os.Getenv("CLICOLOR_FORCE") == "1" {
		return true
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// StderrWidth is the terminal width, then $COLUMNS, then 80.
func StderrWidth() int {
	if cols, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil && cols >= minWidth {
		return cols
	}
	if cols, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && cols >= minWidth {
		return cols
	}
	return defaultWidth
}

// DisplayWidth counts terminal cells, treating East Asian wide runes as two.
func DisplayWidth(s string) int {
	w := 0
	for _, c := range s {
		w += charWidth(c)
	}
	return w
}

func charWidth(c rune) int {
	switch {
	case c == 0 || isControl(c):
		return 0
	case isWide(c):
		return 2
	}
	return 1
}

func isControl(c rune) bool { return c < 0x20 || (c >= 0x7f && c < 0xa0) }

func isWide(c rune) bool {
	switch {
	case c >= 0x1100 && c <= 0x115F, c == 0x2329, c == 0x232A,
		c >= 0x2E80 && c <= 0xA4CF, c >= 0xAC00 && c <= 0xD7A3,
		c >= 0xF900 && c <= 0xFAFF, c >= 0xFE10 && c <= 0xFE19,
		c >= 0xFE30 && c <= 0xFE6F, c >= 0xFF00 && c <= 0xFF60,
		c >= 0xFFE0 && c <= 0xFFE6, c >= 0x1F300 && c <= 0x1F64F,
		c >= 0x1F900 && c <= 0x1F9FF:
		return true
	}
	return false
}

// TruncateCells clips s to max cells, ending in an ellipsis when clipped.
func TruncateCells(s string, maxCells int) string {
	if maxCells == 0 {
		return ""
	}
	if DisplayWidth(s) <= maxCells {
		return s
	}
	if maxCells == 1 {
		return "…"
	}
	var out strings.Builder
	w := 0
	for _, c := range s {
		cw := charWidth(c)
		if w+cw > maxCells-1 {
			break
		}
		out.WriteRune(c)
		w += cw
	}
	out.WriteRune('…')
	return out.String()
}

// StripANSI removes CSI and OSC escape sequences.
func StripANSI(s string) string {
	var out strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c != '\x1b' {
			out.WriteRune(c)
			continue
		}
		if i+1 >= len(runes) {
			continue
		}
		switch runes[i+1] {
		case '[':
			i += 2
			for ; i < len(runes); i++ {
				x := runes[i]
				if (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || x == '~' {
					break
				}
			}
		case ']':
			i += 2
			for ; i < len(runes); i++ {
				if runes[i] == '\x07' {
					break
				}
				if runes[i] == '\x1b' && i+1 < len(runes) && runes[i+1] == '\\' {
					i++
					break
				}
			}
		default:
			i++
		}
	}
	return out.String()
}

// ExposureReport is everything a wrap session exposes to the guest, printed
// at entry.
type ExposureReport struct {
	// Sources is the merge stack that produced this session config.
	Sources []string
	// AllowEverything is true when egress is allow-by-default (dangerous).
	AllowEverything bool
	// Allow is the effective reachable hosts.
	Allow   []string
	Deny    []string
	Secrets []ExposureSecret
	Ports   []string
	Copies  [][2]string
	Env     [][2]string
	// Skipped lists optional secrets whose host source was absent.
	Skipped []string
}

// ExposureSecret is one live secret: the guest holds NOT-AN-ACTUAL-KEY,
// never the real value.
type ExposureSecret struct {
	Env     string
	Headers [][2]string
	Hosts   []string
}

func attachLines(secret ExposureSecret) []string {
	if len(secret.Headers) == 0 {
		return []string{fmt.Sprintf("%s: no headers declared (guest does not see this token)", Sanitize(secret.Env))}
	}
	lines := make([]string, 0, len(secret.Headers))
	for _, header := range secret.Headers {
		lines = append(lines, fmt.Sprintf("%s: %s: %s (guest does not see this token)",
			Sanitize(secret.Env), Sanitize(header[0]), Sanitize(header[1])))
	}
	return lines
}

func FormatExposures(theme Theme, report ExposureReport) string {
	var out strings.Builder
	if len(report.Sources) > 0 {
		out.WriteString("config:\n")
		for _, source := range report.Sources {
			out.WriteString("  " + theme.Primary(Sanitize(source)) + "\n")
		}
	}
	access := theme.OK("deny")
	if report.AllowEverything {
		access = theme.Danger("allow")
	}
	out.WriteString("network-access: " + access + "\n")
	if len(report.Allow) == 0 {
		out.WriteString("  (none)\n")
	}
	// Hosts sharing the exact same credential attachments print as one
	// comma-separated line. Bare hosts share a line too.
	type group struct {
		hosts []string
		lines []string
	}
	var groups []*group
	findGroup := func(lines []string) *group {
		for _, g := range groups {
			if equalStrings(g.lines, lines) {
				return g
			}
		}
		return nil
	}
	for _, host := range report.Allow {
		var attached []string
		for _, secret := range report.Secrets {
			if containsString(secret.Hosts, host) {
				attached = append(attached, attachLines(secret)...)
			}
		}
		if g := findGroup(attached); g != nil {
			g.hosts = append(g.hosts, host)
		} else {
			groups = append(groups, &group{hosts: []string{host}, lines: attached})
		}
	}
	for _, g := range groups {
		out.WriteString("  " + theme.Primary(Sanitize(strings.Join(g.hosts, ", "))) + "\n")
		for _, line := range g.lines {
			out.WriteString("    " + theme.Muted(line) + "\n")
		}
	}
	// Live secrets with no reachable host (every host denied) would
	// otherwise vanish from the report.
	for _, secret := range report.Secrets {
		reachable := false
		for _, host := range secret.Hosts {
			if containsString(report.Allow, host) {
				reachable = true
				break
			}
		}
		if len(secret.Hosts) > 0 && !reachable {
			out.WriteString(fmt.Sprintf("  %s: %s\n", theme.Primary(Sanitize(secret.Env)), theme.Muted("no reachable hosts (all denied)")))
		}
	}
	var deny []string
	for _, host := range report.Deny {
		deny = append(deny, Sanitize(host))
	}
	if !report.AllowEverything {
		deny = append(deny, "everything else")
	}
	if len(deny) > 0 {
		out.WriteString("  deny: " + theme.Muted(strings.Join(deny, ", ")) + "\n")
	}
	if len(report.Ports) > 0 {
		out.WriteString("ports: " + theme.Primary(Sanitize(strings.Join(report.Ports, ", "))) + "\n")
	}
	if len(report.Copies) > 0 {
		var copies []string
		for _, c := range report.Copies {
			copies = append(copies, fmt.Sprintf("%s -> %s", Sanitize(c[0]), Sanitize(c[1])))
		}
		out.WriteString("copies: " + theme.Primary(strings.Join(copies, ", ")) + "\n")
	}
	if len(report.Env) > 0 {
		var env []string
		for _, kv := range report.Env {
			env = append(env, fmt.Sprintf("%s=%s", Sanitize(kv[0]), Sanitize(kv[1])))
		}
		out.WriteString("env: " + theme.Muted(strings.Join(env, " · ")) + "\n")
	}
	if len(report.Skipped) > 0 {
		var names []string
		for _, name := range report.Skipped {
			names = append(names, Sanitize(name))
		}
		out.WriteString("skip: " + theme.Muted(strings.Join(names, ", ")) + "\n")
	}
	return out.String()
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// Sanitize strips escape sequences and control characters from text that
// came from config or the guest.
func Sanitize(s string) string {
	var out strings.Builder
	for _, c := range StripANSI(s) {
		if !isControl(c) {
			out.WriteRune(c)
		}
	}
	return out.String()
}

// RestoreTerminal shows the cursor and resets colors.
func RestoreTerminal() {
	fmt.Fprint(os.Stderr, showCursor+reset)
}
