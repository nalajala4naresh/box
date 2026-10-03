package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/nalajala4naresh/box/internal/agent"
	"github.com/nalajala4naresh/box/internal/config"
)

// ExecOptions describe one guest command.
type ExecOptions struct {
	Argv []string
	// Env entries override the sandbox environment, in order.
	Env     []EnvVar
	Cwd     string
	User    string
	Timeout time.Duration
	Stdin   io.Reader
}

// Output is a finished command.
type Output struct {
	Code   int
	Stdout []byte
	Stderr []byte
}

// Success reports a zero exit.
func (o Output) Success() bool { return o.Code == 0 }

// Env composes the guest environment: image config, sandbox env, secret
// stand-ins, then per-command overrides; later keys win, first position
// kept.
func (s *Sandbox) Env(extra []EnvVar) []string {
	var keys []string
	values := map[string]string{}
	set := func(key, value string) {
		if _, ok := values[key]; !ok {
			keys = append(keys, key)
		}
		values[key] = value
	}
	for _, kv := range s.Spec.ImageEnv {
		if key, value, ok := strings.Cut(kv, "="); ok {
			set(key, value)
		}
	}
	for _, kv := range s.Spec.Env {
		set(kv.Key, kv.Value)
	}
	for _, secret := range s.Spec.Secrets {
		set(secret.Env, config.SecretPlaceholder)
	}
	for _, kv := range extra {
		set(kv.Key, kv.Value)
	}
	if _, ok := values["PATH"]; !ok {
		set("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin")
	}
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

func (s *Sandbox) request(opts ExecOptions, tty bool, rows, cols uint16) (*agent.Conn, net.Conn, error) {
	if len(opts.Argv) == 0 {
		return nil, nil, errors.New("empty command")
	}
	conn, err := net.DialTimeout("unix", AgentSocket(s.st, s.Spec.Name), 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect guest agent: %w", err)
	}
	user := opts.User
	if user == "" {
		user = s.Spec.User
	}
	cwd := opts.Cwd
	if cwd == "" {
		cwd = s.Spec.Workdir
	}
	c := agent.NewConn(conn)
	req := agent.Request{
		Op: "exec", Argv: opts.Argv, Env: s.Env(opts.Env), Cwd: cwd, User: user,
		TTY: tty, Rows: rows, Cols: cols, TimeoutMS: opts.Timeout.Milliseconds(),
	}
	if err := c.WriteJSON(agent.FrameRequest, req); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return c, conn, nil
}

func sendStdin(c *agent.Conn, stdin io.Reader) {
	if stdin != nil {
		c.WriteStream(agent.FrameStdin, stdin)
	}
	c.Write(agent.FrameStdinClose, nil)
}

// Event is one item of a streamed command.
type Event struct {
	Stdout []byte
	Stderr []byte
	// Exited is set on the final event.
	Exited bool
	Code   int
	// Err reports a command that never started or a lost connection.
	Err error
}

// Stream runs a command and delivers its output as it happens. The channel
// closes after the final event.
func (s *Sandbox) Stream(opts ExecOptions) (<-chan Event, func(), error) {
	c, conn, err := s.request(opts, false, 0, 0)
	if err != nil {
		return nil, nil, err
	}
	go sendStdin(c, opts.Stdin)
	events := make(chan Event, 64)
	go func() {
		defer close(events)
		defer conn.Close()
		for {
			typ, payload, err := c.Read()
			if err != nil {
				events <- Event{Err: fmt.Errorf("guest agent connection lost: %w", err)}
				return
			}
			switch typ {
			case agent.FrameStdout:
				events <- Event{Stdout: payload}
			case agent.FrameStderr:
				events <- Event{Stderr: payload}
			case agent.FrameExit:
				var exit agent.Exit
				json.Unmarshal(payload, &exit)
				if exit.Message != "" {
					events <- Event{Stderr: []byte("box: " + exit.Message + "\n")}
				}
				events <- Event{Exited: true, Code: exit.Code}
				return
			case agent.FrameFailed:
				var exit agent.Exit
				json.Unmarshal(payload, &exit)
				events <- Event{Err: errors.New(exit.Message), Code: exit.Code}
				return
			}
		}
	}()
	return events, func() { conn.Close() }, nil
}

// Exec runs a command to completion and collects its output.
func (s *Sandbox) Exec(opts ExecOptions) (Output, error) {
	events, _, err := s.Stream(opts)
	if err != nil {
		return Output{}, err
	}
	var stdout, stderr bytes.Buffer
	for event := range events {
		stdout.Write(event.Stdout)
		stderr.Write(event.Stderr)
		if event.Err != nil {
			return Output{Code: event.Code, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, event.Err
		}
		if event.Exited {
			return Output{Code: event.Code, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
		}
	}
	return Output{}, errors.New("guest agent closed without an exit status")
}

// Shell runs script through the sandbox shell.
func (s *Sandbox) Shell(script string, opts ExecOptions) (Output, error) {
	shell := s.Spec.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	opts.Argv = []string{shell, "-c", script}
	return s.Exec(opts)
}

// ShellStream streams script through the sandbox shell.
func (s *Sandbox) ShellStream(script string, opts ExecOptions) (<-chan Event, func(), error) {
	shell := s.Spec.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	opts.Argv = []string{shell, "-c", script}
	return s.Stream(opts)
}

// Attach runs a command on a guest pty wired to this terminal and returns
// its exit code.
func (s *Sandbox) Attach(opts ExecOptions) (int, error) {
	stdinFD := int(os.Stdin.Fd())
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		cols, rows = 80, 24
	}
	c, conn, err := s.request(opts, true, uint16(rows), uint16(cols))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	state, err := term.MakeRaw(stdinFD)
	if err != nil {
		return 0, fmt.Errorf("raw terminal: %w", err)
	}
	defer term.Restore(stdinFD, state)

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-winch:
				if cols, rows, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
					c.WriteJSON(agent.FrameResize, agent.Resize{Rows: uint16(rows), Cols: uint16(cols)})
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if c.Write(agent.FrameStdin, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		typ, payload, err := c.Read()
		if err != nil {
			return 0, fmt.Errorf("guest agent connection lost: %w", err)
		}
		switch typ {
		case agent.FrameStdout, agent.FrameStderr:
			os.Stdout.Write(payload)
		case agent.FrameExit:
			var exit agent.Exit
			json.Unmarshal(payload, &exit)
			return exit.Code, nil
		case agent.FrameFailed:
			var exit agent.Exit
			json.Unmarshal(payload, &exit)
			return exit.Code, errors.New(exit.Message)
		}
	}
}

// FS operations run through the agent so ownership and mounts behave as
// the guest sees them.

func (s *Sandbox) fsRequest(req agent.Request, body io.Reader) (int, error) {
	conn, err := net.DialTimeout("unix", AgentSocket(s.st, s.Spec.Name), 5*time.Second)
	if err != nil {
		return 0, fmt.Errorf("connect guest agent: %w", err)
	}
	defer conn.Close()
	c := agent.NewConn(conn)
	if err := c.WriteJSON(agent.FrameRequest, req); err != nil {
		return 0, err
	}
	if body != nil {
		if err := c.WriteStream(agent.FrameStdin, body); err != nil {
			return 0, err
		}
		c.Write(agent.FrameStdinClose, nil)
	}
	for {
		typ, payload, err := c.Read()
		if err != nil {
			return 0, fmt.Errorf("guest agent connection lost: %w", err)
		}
		var exit agent.Exit
		json.Unmarshal(payload, &exit)
		switch typ {
		case agent.FrameExit:
			return exit.Code, nil
		case agent.FrameFailed:
			return exit.Code, errors.New(exit.Message)
		}
	}
}

// Exists reports whether a guest path exists.
func (s *Sandbox) Exists(path string) (bool, error) {
	code, err := s.fsRequest(agent.Request{Op: "exists", Path: path}, nil)
	return code == 0 && err == nil, err
}

// Mkdir creates a guest directory and its parents, owned by owner.
func (s *Sandbox) Mkdir(path, owner string) error {
	_, err := s.fsRequest(agent.Request{Op: "mkdir", Path: path, Owner: owner}, nil)
	return err
}

// WriteFile writes a guest file owned by owner.
func (s *Sandbox) WriteFile(path string, data []byte, mode os.FileMode, owner string) error {
	_, err := s.fsRequest(agent.Request{Op: "write", Path: path, Mode: uint32(mode.Perm()), Owner: owner}, bytes.NewReader(data))
	return err
}

// CopyFromHost copies a host file into the guest as root.
func (s *Sandbox) CopyFromHost(host, guest string) error {
	f, err := os.Open(host)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	_, err = s.fsRequest(agent.Request{Op: "write", Path: guest, Mode: uint32(info.Mode().Perm())}, f)
	return err
}
