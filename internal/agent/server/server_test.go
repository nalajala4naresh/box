//go:build linux || darwin

package server

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nalajala4naresh/box/internal/agent"
)

func connect(t *testing.T) *agent.Conn {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	host, err := net.FileConn(os.NewFile(uintptr(fds[0]), "host"))
	if err != nil {
		t.Fatal(err)
	}
	guest := os.NewFile(uintptr(fds[1]), "guest")
	go Handle(guest)
	t.Cleanup(func() { host.Close() })
	host.SetDeadline(time.Now().Add(15 * time.Second))
	return agent.NewConn(host)
}

type result struct {
	stdout, stderr bytes.Buffer
	exit           agent.Exit
	failed         bool
}

func me() string { return strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) }

func run(t *testing.T, req agent.Request, stdin []byte, during func(*agent.Conn)) result {
	t.Helper()
	c := connect(t)
	if req.User == "" {
		req.User = me()
	}
	if req.Op == "" {
		req.Op = "exec"
	}
	if req.Env == nil {
		req.Env = []string{"PATH=" + DefaultPath}
	}
	if err := c.WriteJSON(agent.FrameRequest, req); err != nil {
		t.Fatal(err)
	}
	if stdin != nil {
		c.Write(agent.FrameStdin, stdin)
		c.Write(agent.FrameStdinClose, nil)
	}
	if during != nil {
		go during(c)
	}
	var r result
	for {
		typ, payload, err := c.Read()
		if err != nil {
			t.Fatalf("read: %v (stdout %q stderr %q)", err, r.stdout.String(), r.stderr.String())
		}
		switch typ {
		case agent.FrameStdout:
			r.stdout.Write(payload)
		case agent.FrameStderr:
			r.stderr.Write(payload)
		case agent.FrameExit, agent.FrameFailed:
			json.Unmarshal(payload, &r.exit)
			r.failed = typ == agent.FrameFailed
			return r
		}
	}
}

func TestPing(t *testing.T) {
	r := run(t, agent.Request{Op: "ping"}, nil, nil)
	if r.failed || r.exit.Code != 0 || r.exit.Version != agent.Version {
		t.Fatalf("%+v", r.exit)
	}
}

func TestExecSeparatesStreamsAndExitCode(t *testing.T) {
	r := run(t, agent.Request{Argv: []string{"/bin/sh", "-c", "echo out; echo err >&2; exit 3"}}, nil, nil)
	if r.failed || r.exit.Code != 3 || r.stdout.String() != "out\n" || r.stderr.String() != "err\n" {
		t.Fatalf("%+v %q %q", r.exit, r.stdout.String(), r.stderr.String())
	}
}

func TestExecFeedsStdinAndUsesRequestEnvAndCwd(t *testing.T) {
	dir := t.TempDir()
	r := run(t, agent.Request{
		Argv: []string{"sh", "-c", `cat; printf '%s %s' "$GREETING" "$(pwd -P)"`},
		Env:  []string{"PATH=" + DefaultPath, "GREETING=hello"},
		Cwd:  dir,
	}, []byte("from stdin\n"), nil)
	real, _ := filepath.EvalSymlinks(dir)
	if r.exit.Code != 0 || r.stdout.String() != "from stdin\nhello "+real {
		t.Fatalf("%+v %q %q", r.exit, r.stdout.String(), r.stderr.String())
	}
}

func TestExecOnAPtyWithSize(t *testing.T) {
	r := run(t, agent.Request{Argv: []string{"/bin/sh", "-c", "test -t 0 && echo istty; stty size"}, TTY: true, Rows: 33, Cols: 101}, nil, nil)
	out := strings.ReplaceAll(r.stdout.String(), "\r", "")
	if r.exit.Code != 0 || !strings.Contains(out, "istty\n") || !strings.Contains(out, "33 101") {
		t.Fatalf("%+v %q", r.exit, out)
	}
}

func TestPtyResize(t *testing.T) {
	r := run(t, agent.Request{Argv: []string{"/bin/sh", "-c", "read line; stty size"}, TTY: true, Rows: 10, Cols: 20}, nil, func(c *agent.Conn) {
		c.WriteJSON(agent.FrameResize, agent.Resize{Rows: 40, Cols: 120})
		time.Sleep(100 * time.Millisecond)
		c.Write(agent.FrameStdin, []byte("go\n"))
	})
	if !strings.Contains(r.stdout.String(), "40 120") {
		t.Fatalf("%q", r.stdout.String())
	}
}

func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	start := time.Now()
	r := run(t, agent.Request{Argv: []string{"/bin/sh", "-c", "sleep 30 & sleep 30"}, TimeoutMS: 300}, nil, nil)
	if r.exit.Code != 128+int(syscall.SIGKILL) || r.exit.Message != "timed out" || time.Since(start) > 5*time.Second {
		t.Fatalf("%+v after %s", r.exit, time.Since(start))
	}
}

func TestSignalsReachTheCommand(t *testing.T) {
	r := run(t, agent.Request{Argv: []string{"sleep", "30"}}, nil, func(c *agent.Conn) {
		time.Sleep(200 * time.Millisecond)
		c.Write(agent.FrameSignal, []byte(strconv.Itoa(int(syscall.SIGTERM))))
	})
	if r.exit.Code != 128+int(syscall.SIGTERM) {
		t.Fatalf("%+v", r.exit)
	}
}

func TestMissingCommandFailsToStart(t *testing.T) {
	r := run(t, agent.Request{Argv: []string{"definitely-not-a-command"}}, nil, nil)
	if !r.failed || r.exit.Code != 127 || !strings.Contains(r.exit.Message, "command not found") {
		t.Fatalf("%+v", r)
	}
	r = run(t, agent.Request{Argv: []string{"true"}, Cwd: "/does/not/exist"}, nil, nil)
	if !r.failed || !strings.Contains(r.exit.Message, "does not exist") {
		t.Fatalf("%+v", r)
	}
}

func TestFileOperations(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b")
	if r := run(t, agent.Request{Op: "mkdir", Path: nested, Owner: me()}, nil, nil); r.failed || r.exit.Code != 0 {
		t.Fatalf("mkdir %+v", r.exit)
	}
	file := filepath.Join(nested, "notes.md")
	if r := run(t, agent.Request{Op: "write", Path: file, Mode: 0o600, Owner: me()}, []byte("review notes"), nil); r.failed || r.exit.Code != 0 {
		t.Fatalf("write %+v", r.exit)
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != "review notes" {
		t.Fatal(string(data), err)
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
	if r := run(t, agent.Request{Op: "exists", Path: file}, nil, nil); r.exit.Code != 0 {
		t.Fatal("exists")
	}
	if r := run(t, agent.Request{Op: "exists", Path: filepath.Join(dir, "nope")}, nil, nil); r.exit.Code != 1 {
		t.Fatal("missing")
	}
	if r := run(t, agent.Request{Op: "write", Path: filepath.Join(dir, "missing-parent", "x")}, []byte("x"), nil); !r.failed {
		t.Fatal("write without parent must fail")
	}
}

func TestLookPathUsesRequestPath(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "mytool")
	os.WriteFile(tool, []byte("#!/bin/sh\necho mine\n"), 0o755)
	r := run(t, agent.Request{Argv: []string{"mytool"}, Env: []string{"PATH=" + dir + ":" + DefaultPath}}, nil, nil)
	if r.exit.Code != 0 || r.stdout.String() != "mine\n" {
		t.Fatalf("%+v %q", r.exit, r.stdout.String())
	}
}
