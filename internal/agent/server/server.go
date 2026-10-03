//go:build linux || darwin

// Package server is box-agent's request handling: exec on pipes or a pty,
// and the small file operations the host needs. It builds on macOS too so
// the protocol can be tested without a VM.
package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/nalajala4naresh/box/internal/agent"
)

// DefaultPath is used when a request carries no PATH.
const DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin"

// Handle serves one host connection.
func Handle(f io.ReadWriteCloser) {
	defer f.Close()
	c := agent.NewConn(f)
	typ, payload, err := c.Read()
	if err != nil || typ != agent.FrameRequest {
		return
	}
	var req agent.Request
	if err := json.Unmarshal(payload, &req); err != nil {
		fail(c, 2, "bad request: %v", err)
		return
	}
	switch req.Op {
	case "ping":
		c.WriteJSON(agent.FrameExit, agent.Exit{Code: 0, Version: agent.Version})
	case "exec":
		runExec(c, req)
	case "write":
		runWrite(c, req)
	case "mkdir":
		runMkdir(c, req)
	case "exists":
		code := 1
		if _, err := os.Lstat(req.Path); err == nil {
			code = 0
		}
		c.WriteJSON(agent.FrameExit, agent.Exit{Code: code})
	case "shutdown":
		c.WriteJSON(agent.FrameExit, agent.Exit{Code: 0})
		f.Close()
		Shutdown()
	default:
		fail(c, 2, "unknown op %q", req.Op)
	}
}

func fail(c *agent.Conn, code int, format string, args ...any) {
	c.WriteJSON(agent.FrameFailed, agent.Exit{Code: code, Message: fmt.Sprintf(format, args...)})
}

// Running process groups, so shutdown can stop them before power-off.
var (
	procsMu sync.Mutex
	procs   = map[int]bool{}
)

func track(pid int)   { procsMu.Lock(); procs[pid] = true; procsMu.Unlock() }
func untrack(pid int) { procsMu.Lock(); delete(procs, pid); procsMu.Unlock() }

// Shutdown stops every running command, syncs, and exits so init can
// power the VM off.
func Shutdown() {
	procsMu.Lock()
	pids := make([]int, 0, len(procs))
	for pid := range procs {
		pids = append(pids, pid)
	}
	procsMu.Unlock()
	for _, pid := range pids {
		unix.Kill(-pid, unix.SIGTERM)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		procsMu.Lock()
		left := len(procs)
		procsMu.Unlock()
		if left == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, pid := range pids {
		unix.Kill(-pid, unix.SIGKILL)
	}
	unix.Sync()
	os.Exit(0)
}

type account struct {
	uid, gid uint32
	groups   []uint32
	home     string
}

// lookupUser resolves a guest account by name or numeric uid from
// /etc/passwd and /etc/group, read fresh so uid realignment is honored.
func lookupUser(name string) (account, error) {
	if name == "" {
		name = "root"
	}
	acct := account{home: "/"}
	found := false
	if f, err := os.Open("/etc/passwd"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) < 7 || (fields[0] != name && fields[2] != name) {
				continue
			}
			uid, err1 := strconv.ParseUint(fields[2], 10, 32)
			gid, err2 := strconv.ParseUint(fields[3], 10, 32)
			if err1 != nil || err2 != nil {
				continue
			}
			acct.uid, acct.gid, acct.home = uint32(uid), uint32(gid), fields[5]
			name = fields[0]
			found = true
			break
		}
		f.Close()
	}
	if !found {
		// Numeric "uid" or "uid:gid", like `docker run --user`.
		uidRaw, gidRaw, hasGid := strings.Cut(name, ":")
		uid, err := strconv.ParseUint(uidRaw, 10, 32)
		if err != nil {
			return acct, fmt.Errorf("unknown guest user %q", name)
		}
		gid := uid
		if hasGid {
			if gid, err = strconv.ParseUint(gidRaw, 10, 32); err != nil {
				return acct, fmt.Errorf("unknown guest group in %q", name)
			}
		}
		acct.uid, acct.gid = uint32(uid), uint32(gid)
		return acct, nil
	}
	acct.groups = []uint32{acct.gid}
	if f, err := os.Open("/etc/group"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) < 4 {
				continue
			}
			for _, member := range strings.Split(fields[3], ",") {
				if member == name {
					if gid, err := strconv.ParseUint(fields[2], 10, 32); err == nil && uint32(gid) != acct.gid {
						acct.groups = append(acct.groups, uint32(gid))
					}
				}
			}
		}
		f.Close()
	}
	return acct, nil
}

func envValue(env []string, key string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if k, v, ok := strings.Cut(env[i], "="); ok && k == key {
			return v
		}
	}
	return ""
}

// lookPath searches the request's PATH, not the agent's.
func lookPath(file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		if _, err := os.Stat(file); err != nil {
			return "", err
		}
		return file, nil
	}
	path := envValue(env, "PATH")
	if path == "" {
		path = DefaultPath
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, file)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s: command not found", file)
}

func runExec(c *agent.Conn, req agent.Request) {
	if len(req.Argv) == 0 {
		fail(c, 2, "exec: empty argv")
		return
	}
	acct, err := lookupUser(req.User)
	if err != nil {
		fail(c, 126, "%v", err)
		return
	}
	path, err := lookPath(req.Argv[0], req.Env)
	if err != nil {
		fail(c, 127, "%v", err)
		return
	}
	cmd := &exec.Cmd{Path: path, Args: req.Argv, Env: req.Env, Dir: req.Cwd}
	if cmd.Dir != "" {
		if info, err := os.Stat(cmd.Dir); err != nil || !info.IsDir() {
			fail(c, 126, "working directory %s does not exist", cmd.Dir)
			return
		}
	}
	attr := &syscall.SysProcAttr{Setsid: true}
	if int(acct.uid) != os.Getuid() || int(acct.gid) != os.Getgid() {
		attr.Credential = &syscall.Credential{Uid: acct.uid, Gid: acct.gid, Groups: acct.groups}
	}
	cmd.SysProcAttr = attr

	var (
		ptmx    *os.File
		stdin   io.WriteCloser
		pumps   sync.WaitGroup
		outputs []io.Reader
	)
	if req.TTY {
		master, slave, err := pty.Open()
		if err != nil {
			fail(c, 126, "open pty: %v", err)
			return
		}
		if req.Rows > 0 && req.Cols > 0 {
			pty.Setsize(master, &pty.Winsize{Rows: req.Rows, Cols: req.Cols})
		}
		slave.Chown(int(acct.uid), int(acct.gid))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		attr.Setctty = true
		attr.Ctty = 0
		if err := cmd.Start(); err != nil {
			master.Close()
			slave.Close()
			fail(c, 126, "start %s: %v", req.Argv[0], err)
			return
		}
		slave.Close()
		ptmx = master
		stdin = master
	} else {
		in, err1 := cmd.StdinPipe()
		out, err2 := cmd.StdoutPipe()
		errp, err3 := cmd.StderrPipe()
		if err := errors.Join(err1, err2, err3); err != nil {
			fail(c, 126, "pipes: %v", err)
			return
		}
		if err := cmd.Start(); err != nil {
			fail(c, 126, "start %s: %v", req.Argv[0], err)
			return
		}
		stdin = in
		outputs = []io.Reader{out, errp}
	}
	pid := cmd.Process.Pid
	track(pid)
	defer untrack(pid)

	// Output: one pump per stream. A pty merges both into stdout.
	if ptmx != nil {
		pumps.Add(1)
		go func() {
			defer pumps.Done()
			c.WriteStream(agent.FrameStdout, ptmx)
		}()
	} else {
		for i, r := range outputs {
			typ := agent.FrameStdout
			if i == 1 {
				typ = agent.FrameStderr
			}
			pumps.Add(1)
			go func(r io.Reader, typ byte) {
				defer pumps.Done()
				c.WriteStream(typ, r)
			}(r, typ)
		}
	}

	// Input: stdin, resize, signals. A dropped connection hangs the
	// process group up, then kills it if it lingers.
	exited := make(chan struct{})
	go func() {
		for {
			typ, payload, err := c.Read()
			if err != nil {
				select {
				case <-exited:
					return
				default:
				}
				unix.Kill(-pid, unix.SIGHUP)
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
					unix.Kill(-pid, unix.SIGKILL)
				}
				return
			}
			switch typ {
			case agent.FrameStdin:
				stdin.Write(payload)
			case agent.FrameStdinClose:
				if ptmx == nil {
					stdin.Close()
				}
			case agent.FrameResize:
				var size agent.Resize
				if json.Unmarshal(payload, &size) == nil && ptmx != nil {
					pty.Setsize(ptmx, &pty.Winsize{Rows: size.Rows, Cols: size.Cols})
				}
			case agent.FrameSignal:
				if sig, err := strconv.Atoi(string(payload)); err == nil {
					unix.Kill(-pid, unix.Signal(sig))
				}
			}
		}
	}()

	ctx := context.Background()
	if req.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	var timedOut atomic.Bool
	waitDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				timedOut.Store(true)
				unix.Kill(-pid, unix.SIGKILL)
			}
		case <-waitDone:
		}
	}()

	state, _ := cmd.Process.Wait()
	close(waitDone)
	close(exited)
	code := exitCode(state)

	// Drain what the process left behind, but never hang on descendants
	// that kept the stream open.
	drained := make(chan struct{})
	go func() { pumps.Wait(); close(drained) }()
	grace := 2 * time.Second
	if ptmx != nil {
		grace = 300 * time.Millisecond
	}
	select {
	case <-drained:
	case <-time.After(grace):
	}
	if ptmx != nil {
		ptmx.Close()
	}
	for _, r := range outputs {
		if closer, ok := r.(io.Closer); ok {
			closer.Close()
		}
	}
	exit := agent.Exit{Code: code}
	if timedOut.Load() {
		exit.Message = "timed out"
	}
	c.WriteJSON(agent.FrameExit, exit)
}

func exitCode(state *os.ProcessState) int {
	if state == nil {
		return 125
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return state.ExitCode()
}

func runWrite(c *agent.Conn, req agent.Request) {
	acct, err := lookupUser(req.Owner)
	if err != nil {
		fail(c, 1, "%v", err)
		return
	}
	mode := os.FileMode(req.Mode & 0o7777)
	if mode == 0 {
		mode = 0o644
	}
	tmp := req.Path + ".box-tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		fail(c, 1, "write %s: %v", req.Path, err)
		return
	}
	for {
		typ, payload, err := c.Read()
		if err != nil {
			f.Close()
			os.Remove(tmp)
			return
		}
		if typ == agent.FrameStdinClose {
			break
		}
		if typ == agent.FrameStdin {
			if _, err := f.Write(payload); err != nil {
				f.Close()
				os.Remove(tmp)
				fail(c, 1, "write %s: %v", req.Path, err)
				return
			}
		}
	}
	err = errors.Join(f.Chmod(mode), f.Close())
	if err == nil && req.Owner != "" {
		err = os.Chown(tmp, int(acct.uid), int(acct.gid))
	}
	if err == nil {
		err = os.Rename(tmp, req.Path)
	}
	if err != nil {
		os.Remove(tmp)
		fail(c, 1, "write %s: %v", req.Path, err)
		return
	}
	c.WriteJSON(agent.FrameExit, agent.Exit{Code: 0})
}

func runMkdir(c *agent.Conn, req agent.Request) {
	acct, err := lookupUser(req.Owner)
	if err != nil {
		fail(c, 1, "%v", err)
		return
	}
	var missing []string
	for dir := filepath.Clean(req.Path); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			break
		}
		missing = append(missing, dir)
	}
	if err := os.MkdirAll(req.Path, 0o755); err != nil {
		fail(c, 1, "mkdir %s: %v", req.Path, err)
		return
	}
	if req.Owner != "" {
		for _, dir := range missing {
			os.Chown(dir, int(acct.uid), int(acct.gid))
		}
	}
	c.WriteJSON(agent.FrameExit, agent.Exit{Code: 0})
}
