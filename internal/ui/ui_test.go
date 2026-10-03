package ui

import (
	"fmt"
	"strings"
	"testing"
)

func plain() Theme { return Theme{Color: false} }
func color() Theme { return Theme{Color: true} }

func TestThemeTokensAreDistinct(t *testing.T) {
	c := color()
	for text, want := range map[string]string{
		c.Primary("x"): "38;2;236;239;241m",
		c.Danger("x"):  "38;2;239;83;80m",
		c.Accent("x"):  "38;2;79;195;247m",
		c.OK("x"):      "38;2;129;199;132m",
		c.Warn("x"):    "38;2;247;140;108m",
		c.VM("x"):      "38;2;196;167;231m",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q missing %q", text, want)
		}
	}
	if c.Paint(primaryHex, "") != "" || plain().Danger("x") != "x" {
		t.Fatal("empty and plain painting")
	}
}

func TestCrossingStatesAndWidths(t *testing.T) {
	p := plain()
	wide := FormatCrossing(p, 80, "tobi-xe", "2026-08-13-smolvm", Reused, 4, 4096, 8192)
	if wide != "tobi-xe → vm:2026-08-13-smolvm  ·  reused  ·  4 CPU · 4–8 GiB" {
		t.Fatal(wide)
	}
	if !strings.Contains(FormatCrossing(p, 80, "h", "w", New, 2, 4096, 4096), "new  ·  2 CPU · 4 GiB") {
		t.Fatal("new crossing")
	}
	if !strings.HasSuffix(FormatCrossing(p, 80, "h", "w", Reset, 8, 6144, 8192), "8 CPU · 6–8 GiB") {
		t.Fatal("reset crossing")
	}
	narrow := FormatCrossing(p, 20, "very-long-hostname", "very-long-workspace", Reused, 4, 4096, 8192)
	if DisplayWidth(narrow) > 20 || strings.Contains(narrow, "reused") || !strings.Contains(narrow, "…") {
		t.Fatal(narrow)
	}
}

func TestLayerMarksDifferWithoutColor(t *testing.T) {
	p := plain()
	cases := map[string]string{
		FormatLayerEnd(p, "packages", LayerReused):     "  ·  packages",
		FormatLayerEnd(p, "packages", LayerSnapped):    "  ●  packages",
		FormatLayerFail(p, "languages", "exit 1"):      "  ×  languages  ·  exit 1",
		FormatLayerFail(p, "languages", "interrupted"): "  ×  languages  ·  interrupted",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestLiveLineAlignsSpinnerAndTruncatesPhase(t *testing.T) {
	p := plain()
	line := FormatLiveLine(p, 28, "languages", '⠋', "pacman -S gcc clang make cmake")
	if !strings.HasPrefix(line, "  ⠋ languages  ") || !strings.Contains(line, "…") || DisplayWidth(line) > 28 {
		t.Fatal(line)
	}
	if got := FormatLiveLine(p, 80, "tools", ' ', ""); got != "    tools" {
		t.Fatal(got)
	}
	if []rune(line)[2] != '⠋' || []rune(FormatLayerEnd(p, "languages", LayerReused))[2] != '·' {
		t.Fatal("marks must align at column 2")
	}
}

func TestLiveRegionStreamsTheLatestFourLines(t *testing.T) {
	lines := NewLineBuf()
	lines.Push("line-1\nline-2\nline-3\nline-4\nline-5\npartial\x1b[31m")
	region := formatLiveRegion(plain(), 80, "system", '⠋', "running setup", lines)
	want := "  ⠋ system  running setup\n    line-3\n    line-4\n    line-5\n    partial"
	if region != want {
		t.Fatalf("%q", region)
	}
}

func TestStatusLinesCoverRemainingStates(t *testing.T) {
	p := plain()
	cases := map[string]string{
		FormatRebuild(p, 4):                              "  rebuild  4 layers",
		FormatSetup(p, "base"):                           "setting up base vm",
		FormatSetup(p, "project"):                        "setting up project vm",
		FormatLeftover(p, "box-build-languages", "busy"): "  leftover  box-build-languages  ·  busy",
		FormatStopFailed(p, "timeout"):                   "  stop failed  ·  timeout",
		FormatFatal(p, "layer languages failed"):         "box  layer languages failed",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestColorIsOptionalDecoration(t *testing.T) {
	render := func(th Theme) []string {
		return []string{
			FormatCrossing(th, 80, "host", "ws", New, 4, 4096, 8192),
			FormatLayerEnd(th, "packages", LayerSnapped),
			FormatLayerFail(th, "languages", "exit 1"),
			FormatLiveLine(th, 80, "tools", '⠋', "mise use rust"),
			FormatSetup(th, "base"),
			FormatRebuild(th, 4),
			FormatFatal(th, "interrupted"),
		}
	}
	plainLines, colorLines := render(plain()), render(color())
	for i := range plainLines {
		if plainLines[i] != StripANSI(colorLines[i]) || strings.Contains(plainLines[i], "\x1b") ||
			!strings.Contains(colorLines[i], "\x1b[38;2;") {
			t.Fatalf("%q vs %q", plainLines[i], colorLines[i])
		}
	}
}

func TestLineBufHandlesCRAndANSI(t *testing.T) {
	buf := NewLineBuf()
	buf.Push("box: layer packages\n")
	buf.Push("downloading\r")
	buf.Push("\x1b[32m100%\x1b[0m\n")
	buf.Push("partial")
	if buf.Snippet() != "partial" {
		t.Fatal(buf.Snippet())
	}
	if fmt.Sprint(buf.History()) != "[box: layer packages 100%]" {
		t.Fatal(buf.History())
	}
}

func TestSanitizeStripsControlsAndCSI(t *testing.T) {
	if Sanitize("a\x1b[31mb\x07c") != "abc" || DisplayWidth("日本語") != 6 ||
		TruncateCells("日本語", 5) != "日本…" || TruncateCells("abc", 10) != "abc" {
		t.Fatal("sanitize/truncate")
	}
}

func TestHistoryIsBounded(t *testing.T) {
	buf := NewLineBuf()
	for i := 0; i < 80; i++ {
		buf.Push(fmt.Sprintf("line-%d\n", i))
	}
	if len(buf.History()) != historyCap || buf.History()[0] != "line-32" {
		t.Fatal(buf.History())
	}
}

func exposureFixture(allowEverything bool) ExposureReport {
	return ExposureReport{
		Sources:         []string{"embedded defaults", "~/.config/box/config.yml"},
		AllowEverything: allowEverything,
		Allow:           []string{"github.com", "mise.run"},
		Deny:            []string{"blocked.example.com"},
		Secrets: []ExposureSecret{{
			Env:     "GH_TOKEN",
			Headers: [][2]string{{"Authorization", "Bearer $GH_TOKEN"}},
			Hosts:   []string{"github.com"},
		}},
		Ports:  []string{"6080"},
		Copies: [][2]string{{"pi", "/home/user/.pi"}},
		Env:    [][2]string{{"TERM", "xterm-256color"}},
	}
}

func TestExposuresListHostsWithCredentialLines(t *testing.T) {
	text := FormatExposures(plain(), exposureFixture(false))
	for _, want := range []string{
		"config:\n  embedded defaults\n  ~/.config/box/config.yml\nnetwork-access: deny",
		"  github.com\n    GH_TOKEN: Authorization: Bearer $GH_TOKEN (guest does not see this token)",
		"  mise.run\n",
		"  deny: blocked.example.com, everything else",
		"ports: 6080",
		"copies: pi -> /home/user/.pi",
		"env: TERM=xterm-256color",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	for _, never := range []string{"no credential", "(none)", "real-token", "NOT-AN-ACTUAL-KEY"} {
		if strings.Contains(text, never) {
			t.Fatalf("unexpected %q in:\n%s", never, text)
		}
	}
}

func TestExposuresGroupHostsSharingOneCredential(t *testing.T) {
	report := exposureFixture(false)
	report.Allow = []string{"github.com", "mise.run", "api.github.com"}
	report.Secrets[0].Hosts = []string{"github.com", "api.github.com"}
	text := FormatExposures(plain(), report)
	if !strings.Contains(text, "  github.com, api.github.com\n    GH_TOKEN: Authorization: Bearer $GH_TOKEN") ||
		!strings.Contains(text, "  mise.run\n") {
		t.Fatal(text)
	}
}

func TestExposuresShowDefaultDenyWithoutAList(t *testing.T) {
	report := exposureFixture(false)
	report.Deny = nil
	if !strings.Contains(FormatExposures(plain(), report), "  deny: everything else") {
		t.Fatal("default deny line")
	}
	report.AllowEverything = true
	if strings.Contains(FormatExposures(plain(), report), "deny:") {
		t.Fatal("allow-everything has no deny line")
	}
}

func TestExposuresFlagSecretsWithoutHeaders(t *testing.T) {
	report := exposureFixture(false)
	report.Secrets[0].Headers = nil
	if !strings.Contains(FormatExposures(plain(), report), "GH_TOKEN: no headers declared (guest does not see this token)") {
		t.Fatal("headerless secret")
	}
}

func TestExposuresPaintAllowRedAndDenyGreen(t *testing.T) {
	denied := FormatExposures(color(), exposureFixture(false))
	if !strings.Contains(denied, "network-access: \x1b[38;2;129;199;132mdeny\x1b[0m") {
		t.Fatal(denied)
	}
	allowed := FormatExposures(color(), exposureFixture(true))
	if !strings.Contains(allowed, "network-access: \x1b[38;2;239;83;80mallow\x1b[0m") {
		t.Fatal(allowed)
	}
	if StripANSI(allowed) != FormatExposures(plain(), exposureFixture(true)) {
		t.Fatal("colored output must strip back to plain")
	}
}

func TestExposuresSurfaceFullyDeniedSecrets(t *testing.T) {
	report := exposureFixture(false)
	report.Allow = []string{"mise.run"}
	report.Deny = append(report.Deny, "github.com")
	if !strings.Contains(FormatExposures(plain(), report), "GH_TOKEN: no reachable hosts (all denied)") {
		t.Fatal("fully denied secret")
	}
}

func TestExposuresOmitEmptyPortsCopiesAndGroupBareHosts(t *testing.T) {
	report := exposureFixture(false)
	report.Ports = nil
	report.Copies = nil
	report.Allow = []string{"github.com", "mise.run", "pypi.org"}
	report.Skipped = []string{"OPENAI_API_KEY"}
	text := FormatExposures(plain(), report)
	if strings.Contains(text, "ports:") || strings.Contains(text, "copies:") ||
		!strings.Contains(text, "  mise.run, pypi.org\n") || !strings.Contains(text, "skip: OPENAI_API_KEY") {
		t.Fatal(text)
	}
}
