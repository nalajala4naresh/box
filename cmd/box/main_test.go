package main

// Fail-fast CLI behavior: unknown bare commands and `box log` without a
// session must error immediately instead of booting a VM.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("BOX_TEST_RUN_MAIN") == "1" {
		os.Args = append([]string{"box"}, strings.Split(os.Getenv("BOX_TEST_ARGS"), "\x1f")...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type result struct {
	code           int
	stdout, stderr string
}

// box runs this test binary as `box` with an isolated home and config.
func box(t *testing.T, dir string, args ...string) result {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(os.Args[0])
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"BOX_TEST_RUN_MAIN=1",
		"BOX_TEST_ARGS="+strings.Join(args, "\x1f"),
		"HOME="+home,
		"BOX_HOME="+filepath.Join(home, ".box"),
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"NO_COLOR=1",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestUnknownBareCommandFailsWithoutBooting(t *testing.T) {
	out := box(t, t.TempDir(), "definitely-not-a-box-command")
	if out.code == 0 {
		t.Fatalf("unknown command must fail: %+v", out)
	}
	if !strings.Contains(out.stderr, "unknown command") || !strings.Contains(out.stderr, "box --") {
		t.Fatalf("stderr names the problem and the escape hatch: %s", out.stderr)
	}
	if strings.Contains(out.stderr, "setting up project vm") {
		t.Fatalf("must fail before any VM work: %s", out.stderr)
	}
}

func TestLogWithoutSessionFailsCleanly(t *testing.T) {
	out := box(t, t.TempDir(), "log")
	if out.code == 0 || !strings.Contains(out.stderr, "no box session") {
		t.Fatalf("%+v", out)
	}
}

func TestLogHelpListsOptions(t *testing.T) {
	out := box(t, t.TempDir(), "log", "--help")
	if out.code != 0 || !strings.Contains(out.stdout, "--tail") || !strings.Contains(out.stdout, "--follow") {
		t.Fatalf("%+v", out)
	}
}

func TestMethodWithoutSessionPointsAtStarting(t *testing.T) {
	dir := t.TempDir()
	out := box(t, dir, "-c", dir, "ls")
	if out.code == 0 || !strings.Contains(out.stderr, "no box for") || !strings.Contains(out.stderr, "start one with box -c") {
		t.Fatalf("%+v", out)
	}
}

func TestInitAllowAndConfigNeverBoot(t *testing.T) {
	dir := t.TempDir()
	if out := box(t, dir, "init"); out.code != 0 || !strings.Contains(out.stdout, "wrote ") {
		t.Fatalf("init: %+v", out)
	}
	if out := box(t, dir, "init"); out.code == 0 || !strings.Contains(out.stderr, "already exists") {
		t.Fatalf("second init: %+v", out)
	}
	if out := box(t, dir, "allow", ".example.com"); out.code != 0 || !strings.Contains(out.stdout, "allowed .example.com") {
		t.Fatalf("allow: %+v", out)
	}
	out := box(t, dir, "config")
	if out.code != 0 || !strings.Contains(out.stdout, ".example.com") || !strings.Contains(out.stdout, "image: ghcr.io/tobi/wrap:latest") {
		t.Fatalf("config: %+v", out)
	}
	if strings.Contains(out.stdout, "NOT-AN-ACTUAL-KEY") {
		t.Fatal("config dump must not print the stand-in")
	}
}

func TestSkillPrints(t *testing.T) {
	out := box(t, t.TempDir(), "--skill")
	if out.code != 0 || !strings.HasPrefix(out.stdout, "---\nname: box") {
		t.Fatalf("%+v", out)
	}
}
