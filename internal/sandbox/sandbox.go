package sandbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/nalajala4naresh/box/internal/agent"
	"github.com/nalajala4naresh/box/internal/agentbin"
	"github.com/nalajala4naresh/box/internal/netstack"
	"github.com/nalajala4naresh/box/internal/store"
)

// Status is a sandbox's runtime state.
type Status int

const (
	Stopped Status = iota
	Running
	// Draining means a stop was requested and the VM is still shutting
	// down.
	Draining
)

func (s Status) String() string {
	switch s {
	case Running:
		return "running"
	case Draining:
		return "draining"
	}
	return "stopped"
}

// Sandbox is a handle on one named sandbox.
type Sandbox struct {
	st   *store.Store
	Spec Spec
}

// Source is what a new sandbox's rootfs is cloned from.
type Source struct {
	// Snapshot names a snapshot to clone.
	Snapshot string
	// ImageRootfs and ImageDigest describe an extracted image to clone.
	ImageRootfs string
	ImageDigest string
	ImageEnv    []string
}

// Get opens an existing sandbox.
func Get(st *store.Store, name string) (*Sandbox, error) {
	spec, err := LoadSpec(st, name)
	if err != nil {
		return nil, err
	}
	return &Sandbox{st: st, Spec: spec}, nil
}

// Name is the sandbox's name.
func (s *Sandbox) Name() string { return s.Spec.Name }

// Status reports the current runtime state.
func (s *Sandbox) Status() Status { return StatusOf(s.st, s.Spec.Name) }

// Refresh rereads the spec from disk.
func (s *Sandbox) Refresh() error {
	spec, err := LoadSpec(s.st, s.Spec.Name)
	if err != nil {
		return err
	}
	s.Spec = spec
	return nil
}

// children tracks VM processes this process spawned, so their exit is seen
// even while they linger as unreaped zombies.
var children sync.Map // pid -> chan struct{} closed on exit

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if done, ok := children.Load(pid); ok {
		select {
		case <-done.(chan struct{}):
			return false
		default:
			return true
		}
	}
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}

func readPid(st *store.Store, name string) int {
	data, err := os.ReadFile(pidPath(st, name))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

// StatusOf reports a sandbox's runtime state without loading its spec.
func StatusOf(st *store.Store, name string) Status {
	pid := readPid(st, name)
	if !processAlive(pid) {
		return Stopped
	}
	// A recycled pid is not our VM: a live VM process always has its
	// control socket (ours may still be booting).
	if _, ours := children.Load(pid); !ours && !store.Exists(ControlSocket(st, name)) {
		return Stopped
	}
	if store.Exists(stoppingPath(st, name)) {
		return Draining
	}
	return Running
}

// Create builds a sandbox from source, replacing any sandbox of the same
// name, and boots it.
func Create(st *store.Store, spec Spec, source Source, secrets []netstack.Secret) (*Sandbox, error) {
	unlock, err := store.Lock(filepath.Join(st.RunDir(spec.Name) + ".lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := remove(st, spec.Name); err != nil {
		return nil, err
	}
	dir := st.SandboxDir(spec.Name)
	if err := os.MkdirAll(LogsDir(st, spec.Name), 0o700); err != nil {
		return nil, err
	}
	switch {
	case source.Snapshot != "":
		snap, err := OpenSnapshot(st, source.Snapshot)
		if err != nil {
			return nil, err
		}
		if err := store.Clone(SnapshotRootfs(st, source.Snapshot), RootfsPath(st, spec.Name)); err != nil {
			store.RemoveAll(dir)
			return nil, err
		}
		spec.Base = source.Snapshot
		spec.ImageEnv = snap.ImageEnv
	case source.ImageRootfs != "":
		if err := store.Clone(source.ImageRootfs, RootfsPath(st, spec.Name)); err != nil {
			store.RemoveAll(dir)
			return nil, err
		}
		spec.Base = source.ImageDigest
		spec.ImageEnv = source.ImageEnv
	default:
		return nil, errors.New("sandbox needs a snapshot or image source")
	}
	if spec.Labels == nil {
		spec.Labels = map[string]string{}
	}
	if err := saveSpec(st, spec); err != nil {
		store.RemoveAll(dir)
		return nil, err
	}
	sb := &Sandbox{st: st, Spec: spec}
	if err := sb.start(secrets); err != nil {
		return nil, err
	}
	return sb, nil
}

// Remove stops a sandbox if needed and deletes it.
func Remove(st *store.Store, name string) error {
	unlock, err := store.Lock(filepath.Join(st.RunDir(name) + ".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return remove(st, name)
}

func remove(st *store.Store, name string) error {
	if StatusOf(st, name) != Stopped {
		sb := &Sandbox{st: st, Spec: Spec{Name: name}}
		if err := sb.Stop(); err != nil {
			return err
		}
	}
	if err := store.RemoveAll(st.SandboxDir(name)); err != nil {
		return fmt.Errorf("remove sandbox %s: %w", name, err)
	}
	return store.RemoveAll(st.RunDir(name))
}

// Start boots a stopped sandbox. The VM keeps running after this process
// exits until something stops it.
func (s *Sandbox) Start(secrets []netstack.Secret) error {
	unlock, err := store.Lock(filepath.Join(s.st.RunDir(s.Spec.Name) + ".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if s.Status() == Running {
		return nil
	}
	return s.start(secrets)
}

// Connect verifies a running sandbox's agent answers.
func (s *Sandbox) Connect() error {
	return s.ping()
}

func (s *Sandbox) start(secrets []netstack.Secret) error {
	name := s.Spec.Name
	run := s.st.RunDir(name)
	if err := os.MkdirAll(run, 0o700); err != nil {
		return err
	}
	for _, path := range []string{AgentSocket(s.st, name), ControlSocket(s.st, name), pidPath(s.st, name), stoppingPath(s.st, name)} {
		os.Remove(path)
	}
	if err := s.installGuestFiles(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(LogsDir(s.st, name), 0o700); err != nil {
		return err
	}
	console, err := os.OpenFile(filepath.Join(LogsDir(s.st, name), "console.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer console.Close()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devnull.Close()
	secretsR, secretsW, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "__vm", name)
	cmd.Env = append(os.Environ(), "BOX_HOME="+s.st.Root)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, console, console
	cmd.ExtraFiles = []*os.File{secretsR}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		secretsR.Close()
		secretsW.Close()
		return fmt.Errorf("start vm process: %w", err)
	}
	secretsR.Close()
	payload, _ := json.Marshal(secrets)
	secretsW.Write(payload)
	secretsW.Close()

	done := make(chan struct{})
	children.Store(cmd.Process.Pid, done)
	go func() { cmd.Wait(); close(done) }()
	if err := os.WriteFile(pidPath(s.st, name), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		return err
	}

	deadline := time.Now().Add(90 * time.Second)
	for {
		select {
		case <-done:
			return fmt.Errorf("vm %s exited during boot%s%s", name, consoleTail(s.st, name), bootHint(s.st, name))
		default:
		}
		if err := s.ping(); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			unix.Kill(cmd.Process.Pid, unix.SIGKILL)
			return fmt.Errorf("vm %s did not come up within 90s%s", name, consoleTail(s.st, name))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// bootHint explains the failures with a known cause.
func bootHint(st *store.Store, name string) string {
	data, _ := os.ReadFile(filepath.Join(LogsDir(st, name), "console.log"))
	if runtime.GOOS == "darwin" && bytes.Contains(data, []byte("VmCreate")) {
		exe, _ := os.Executable()
		return "\n  macOS refused to create the VM: this binary lacks the com.apple.security.hypervisor entitlement." +
			"\n  build with `make`, or sign it: codesign --entitlements entitlements.plist --force -s - " + exe
	}
	return ""
}

func consoleTail(st *store.Store, name string) string {
	data, err := os.ReadFile(filepath.Join(LogsDir(st, name), "console.log"))
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	return ":\n  " + strings.Join(lines, "\n  ")
}

// installGuestFiles writes box's guest plumbing into the rootfs: the agent
// binary, the boot configuration, and the interception CA certificate.
func (s *Sandbox) installGuestFiles() error {
	rootfs := RootfsPath(s.st, s.Spec.Name)
	bin, err := agentbin.Binary()
	if err != nil {
		return err
	}
	if err := store.WriteRootFile(rootfs, agent.AgentPath, bin, 0o755, 0, 0); err != nil {
		return fmt.Errorf("install guest agent: %w", err)
	}
	ca, err := netstack.LoadOrCreateCA(s.st.CADir())
	if err != nil {
		return fmt.Errorf("box CA: %w", err)
	}
	const caPath = "/.box/ca.pem"
	if err := store.WriteRootFile(rootfs, caPath, ca.CertPEM, 0o644, 0, 0); err != nil {
		return err
	}
	boot := agent.Boot{
		Hostname: s.Spec.Hostname,
		Net: &agent.Net{
			Iface:   "eth0",
			Address: netstack.GuestCIDR,
			Gateway: netstack.GatewayIP.String(),
			DNS:     netstack.GatewayIP.String(),
			MTU:     netstack.MTU,
		},
		Timezone: s.Spec.Timezone,
		CAPath:   caPath,
	}
	for i, vol := range s.Spec.Volumes {
		boot.Mounts = append(boot.Mounts, agent.Mount{Tag: VolumeTag(i), Path: vol.Guest, ReadOnly: vol.ReadOnly})
	}
	data, _ := json.MarshalIndent(boot, "", "  ")
	return store.WriteRootFile(rootfs, agent.BootPath, data, 0o644, 0, 0)
}

// VolumeTag is the virtio-fs tag of the i-th volume.
func VolumeTag(i int) string { return fmt.Sprintf("boxvol%d", i) }

func (s *Sandbox) ping() error {
	conn, err := net.DialTimeout("unix", AgentSocket(s.st, s.Spec.Name), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	c := agent.NewConn(conn)
	if err := c.WriteJSON(agent.FrameRequest, agent.Request{Op: "ping"}); err != nil {
		return err
	}
	typ, payload, err := c.Read()
	if err != nil {
		return err
	}
	if typ != agent.FrameExit {
		return fmt.Errorf("unexpected agent reply %q", typ)
	}
	var exit agent.Exit
	json.Unmarshal(payload, &exit)
	if exit.Version != agent.Version {
		return fmt.Errorf("guest agent speaks protocol %d, want %d", exit.Version, agent.Version)
	}
	return nil
}

// RequestStop asks the guest to shut down and returns without waiting.
func (s *Sandbox) RequestStop() error {
	name := s.Spec.Name
	pid := readPid(s.st, name)
	if !processAlive(pid) {
		return nil
	}
	os.WriteFile(stoppingPath(s.st, name), nil, 0o600)
	conn, err := net.DialTimeout("unix", AgentSocket(s.st, name), 2*time.Second)
	if err != nil {
		return unix.Kill(pid, unix.SIGTERM)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	c := agent.NewConn(conn)
	if err := c.WriteJSON(agent.FrameRequest, agent.Request{Op: "shutdown"}); err != nil {
		return unix.Kill(pid, unix.SIGTERM)
	}
	c.Read()
	return nil
}

// WaitStopped waits for the VM process to exit.
func (s *Sandbox) WaitStopped(timeout time.Duration) error {
	pid := readPid(s.st, s.Spec.Name)
	deadline := time.Now().Add(timeout)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			return fmt.Errorf("vm %s did not stop within %s", s.Spec.Name, timeout)
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil
}

// Stop shuts the VM down gracefully, killing it if it will not go.
func (s *Sandbox) Stop() error {
	if err := s.RequestStop(); err != nil {
		return err
	}
	if err := s.WaitStopped(20 * time.Second); err != nil {
		pid := readPid(s.st, s.Spec.Name)
		unix.Kill(pid, unix.SIGKILL)
		if err := s.WaitStopped(5 * time.Second); err != nil {
			return err
		}
	}
	os.Remove(stoppingPath(s.st, s.Spec.Name))
	return nil
}

// SetResources changes CPUs and memory; the VM restarts to apply them.
func (s *Sandbox) SetResources(cpus uint8, memory, maxMemory uint32, secrets []netstack.Secret) error {
	wasRunning := s.Status() != Stopped
	if wasRunning {
		if err := s.Stop(); err != nil {
			return err
		}
	}
	s.Spec.CPUs, s.Spec.Memory, s.Spec.MaxMem = cpus, memory, maxMemory
	if err := saveSpec(s.st, s.Spec); err != nil {
		return err
	}
	if wasRunning {
		return s.Start(secrets)
	}
	return nil
}

// SetLabel persists one label.
func (s *Sandbox) SetLabel(key, value string) error {
	if s.Spec.Labels == nil {
		s.Spec.Labels = map[string]string{}
	}
	s.Spec.Labels[key] = value
	return saveSpec(s.st, s.Spec)
}

// UpdateSecrets rotates live secret values in the running VM's network.
func (s *Sandbox) UpdateSecrets(secrets []netstack.Secret) error {
	conn, err := net.DialTimeout("unix", ControlSocket(s.st, s.Spec.Name), 2*time.Second)
	if err != nil {
		return fmt.Errorf("vm control socket: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(ControlRequest{Op: "secrets", Secrets: secrets}); err != nil {
		return err
	}
	var reply ControlReply
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&reply); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	return nil
}

// ControlRequest is one request on a VM process's control socket.
type ControlRequest struct {
	Op      string            `json:"op"`
	Secrets []netstack.Secret `json:"secrets,omitempty"`
}

// ControlReply answers a ControlRequest.
type ControlReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// LogEntry is one line of a sandbox's system log.
type LogEntry struct {
	Timestamp string
	Body      string
}

// Logs reads the sandbox's network and runtime diagnostics.
func (s *Sandbox) Logs() ([]LogEntry, error) {
	f, err := os.Open(filepath.Join(LogsDir(s.st, s.Spec.Name), "system.log"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []LogEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		ts, body, _ := strings.Cut(scanner.Text(), " ")
		entries = append(entries, LogEntry{Timestamp: ts, Body: body})
	}
	return entries, scanner.Err()
}
