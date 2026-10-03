// Package sandbox is wrap's VM runtime: persistent named sandboxes whose
// rootfs is a copy-on-write clone of a snapshot or image, each booted by a
// detached `wrap __vm` process that hosts libkrun and the VM's userspace
// network. The host talks to the guest agent over a vsock-mapped socket.
package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nalajala4naresh/box/internal/netstack"
	"github.com/nalajala4naresh/box/internal/store"
)

// EnvVar is one ordered environment entry.
type EnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Volume is a host directory shared into the guest over virtio-fs.
type Volume struct {
	Host     string `json:"host"`
	Guest    string `json:"guest"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// SecretDecl is a secret's structure: never its value. Values travel to the
// VM process over a pipe or the control socket and stay in memory.
type SecretDecl struct {
	Env     string   `json:"env"`
	Hosts   []string `json:"hosts"`
	Headers []string `json:"headers,omitempty"`
}

// Spec is everything a sandbox is created with.
type Spec struct {
	Name     string                 `json:"name"`
	Labels   map[string]string      `json:"labels,omitempty"`
	CPUs     uint8                  `json:"cpus"`
	Memory   uint32                 `json:"memory_mib"`
	MaxMem   uint32                 `json:"max_memory_mib"`
	User     string                 `json:"user"`
	Shell    string                 `json:"shell"`
	Workdir  string                 `json:"workdir,omitempty"`
	Hostname string                 `json:"hostname,omitempty"`
	Env      []EnvVar               `json:"env,omitempty"`
	ImageEnv []string               `json:"image_env,omitempty"`
	Volumes  []Volume               `json:"volumes,omitempty"`
	Ports    []netstack.PortForward `json:"ports,omitempty"`
	Policy   netstack.Policy        `json:"policy"`
	Secrets  []SecretDecl           `json:"secrets,omitempty"`
	// Base names the snapshot or image digest the rootfs was cloned from.
	Base     string `json:"base"`
	Timezone string `json:"timezone,omitempty"`
}

func specPath(st *store.Store, name string) string {
	return filepath.Join(st.SandboxDir(name), "sandbox.json")
}

// RootfsPath is the sandbox's root filesystem on the host.
func RootfsPath(st *store.Store, name string) string {
	return filepath.Join(st.SandboxDir(name), "rootfs")
}

// LogsDir holds console.log and system.log.
func LogsDir(st *store.Store, name string) string {
	return filepath.Join(st.SandboxDir(name), "logs")
}

// AgentSocket is the host end of the guest agent's vsock port.
func AgentSocket(st *store.Store, name string) string {
	return filepath.Join(st.RunDir(name), "agent.sock")
}

// ControlSocket is the VM process's control endpoint.
func ControlSocket(st *store.Store, name string) string {
	return filepath.Join(st.RunDir(name), "ctl.sock")
}

func pidPath(st *store.Store, name string) string {
	return filepath.Join(st.RunDir(name), "vm.pid")
}

func stoppingPath(st *store.Store, name string) string {
	return filepath.Join(st.RunDir(name), "stopping")
}

// LoadSpec reads a sandbox's spec.
func LoadSpec(st *store.Store, name string) (Spec, error) {
	data, err := os.ReadFile(specPath(st, name))
	if err != nil {
		return Spec{}, fmt.Errorf("sandbox %s not found", name)
	}
	var spec Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return Spec{}, fmt.Errorf("sandbox %s: %w", name, err)
	}
	return spec, nil
}

func saveSpec(st *store.Store, spec Spec) error {
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	path := specPath(st, spec.Name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
