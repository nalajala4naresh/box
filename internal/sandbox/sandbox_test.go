package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nalajala4naresh/box/internal/agent/server"
	"github.com/nalajala4naresh/box/internal/netstack"
	"github.com/nalajala4naresh/box/internal/store"
)

// fakeVM serves the real agent request handler on the sandbox's agent
// socket, standing in for the VM.
func fakeVM(t *testing.T, spec Spec) *Sandbox {
	t.Helper()
	// Keep sun_path short.
	root, err := os.MkdirTemp("/tmp", "boxt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	st := &store.Store{Root: root, Data: filepath.Join(root, "data")}
	os.MkdirAll(st.SandboxDir(spec.Name), 0o700)
	os.MkdirAll(st.RunDir(spec.Name), 0o700)
	if err := saveSpec(st, spec); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", AgentSocket(st, spec.Name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go server.Handle(conn)
		}
	}()
	sb, err := Get(st, spec.Name)
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func me() string { return strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) }

func TestEnvLayersImageSpecSecretsAndOverrides(t *testing.T) {
	sb := &Sandbox{Spec: Spec{
		ImageEnv: []string{"PATH=/image/bin", "LANG=C", "HOME=/root"},
		Env:      []EnvVar{{"HOME", "/home/user"}, {"TERM", "xterm"}},
		Secrets:  []SecretDecl{{Env: "GH_TOKEN"}},
	}}
	got := strings.Join(sb.Env([]EnvVar{{"HOME", "/root"}, {"EXTRA", "1"}}), " ")
	want := "PATH=/image/bin LANG=C HOME=/root TERM=xterm GH_TOKEN=NOT-AN-ACTUAL-KEY EXTRA=1"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if env := (&Sandbox{}).Env(nil); len(env) != 1 || !strings.HasPrefix(env[0], "PATH=") {
		t.Fatal(env)
	}
}

func TestExecShellAndFilesThroughTheAgent(t *testing.T) {
	workdir := t.TempDir()
	sb := fakeVM(t, Spec{
		Name:    "box-test",
		User:    me(),
		Shell:   "/bin/sh",
		Workdir: workdir,
		Env:     []EnvVar{{"GREETING", "hi"}},
		Secrets: []SecretDecl{{Env: "API_KEY"}},
	})
	out, err := sb.Shell(`printf '%s %s %s' "$GREETING" "$API_KEY" "$(basename "$(pwd)")"`, ExecOptions{})
	if err != nil || out.Code != 0 {
		t.Fatal(out, err)
	}
	if string(out.Stdout) != "hi NOT-AN-ACTUAL-KEY "+filepath.Base(workdir) {
		t.Fatalf("%q", out.Stdout)
	}
	out, _ = sb.Exec(ExecOptions{Argv: []string{"/bin/sh", "-c", "exit 7"}})
	if out.Code != 7 || out.Success() {
		t.Fatal(out)
	}
	if _, err := sb.Exec(ExecOptions{Argv: []string{"no-such-binary-here"}}); err == nil {
		t.Fatal("start failure must be an error")
	}

	target := filepath.Join(workdir, "sub", "notes.md")
	if err := sb.Mkdir(filepath.Dir(target), me()); err != nil {
		t.Fatal(err)
	}
	if err := sb.WriteFile(target, []byte("hello"), 0o644, me()); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(target); string(data) != "hello" {
		t.Fatal(string(data))
	}
	if ok, _ := sb.Exists(target); !ok {
		t.Fatal("exists")
	}
	host := filepath.Join(t.TempDir(), "host.txt")
	os.WriteFile(host, []byte("from host"), 0o640)
	copied := filepath.Join(workdir, "copied.txt")
	if err := sb.CopyFromHost(host, copied); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(copied); string(data) != "from host" {
		t.Fatal(string(data))
	}

	events, _, err := sb.Stream(ExecOptions{Argv: []string{"/bin/sh", "-c", "echo one; echo two >&2"}})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr string
	code := -1
	for event := range events {
		stdout += string(event.Stdout)
		stderr += string(event.Stderr)
		if event.Exited {
			code = event.Code
		}
	}
	if stdout != "one\n" || stderr != "two\n" || code != 0 {
		t.Fatalf("%q %q %d", stdout, stderr, code)
	}
}

func TestStatusOfAStoppedSandbox(t *testing.T) {
	root, _ := os.MkdirTemp("/tmp", "boxt")
	defer os.RemoveAll(root)
	st := &store.Store{Root: root, Data: filepath.Join(root, "data")}
	if StatusOf(st, "absent") != Stopped {
		t.Fatal("absent sandboxes are stopped")
	}
	os.MkdirAll(st.RunDir("stale"), 0o700)
	// A pid that is alive but not a VM (this test process, no control
	// socket) must not read as running.
	os.WriteFile(pidPath(st, "stale"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	if StatusOf(st, "stale") != Stopped {
		t.Fatal("a recycled pid without a control socket is not a running VM")
	}
}

func TestLogsParseTimestampAndBody(t *testing.T) {
	root, _ := os.MkdirTemp("/tmp", "boxt")
	defer os.RemoveAll(root)
	st := &store.Store{Root: root, Data: filepath.Join(root, "data")}
	os.MkdirAll(LogsDir(st, "s"), 0o700)
	logger, _ := netstack.OpenLogger(filepath.Join(LogsDir(st, "s"), "system.log"))
	logger.Debugf("DNS query denied by network policy domain=x.test")
	sb := &Sandbox{st: st, Spec: Spec{Name: "s"}}
	entries, err := sb.Logs()
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	if !strings.HasSuffix(entries[0].Timestamp, "Z") || entries[0].Body != "DEBUG DNS query denied by network policy domain=x.test" {
		t.Fatalf("%+v", entries[0])
	}
}
