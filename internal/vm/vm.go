// Package vm is the `box __vm <sandbox>` process: it brings up the
// sandbox's userspace network and control socket, configures libkrun
// through libkrun-go, and hands the process to krun_start_enter. libkrun
// never returns from that call on success; the process exits with the
// guest's exit code when the VM powers off.
package vm

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/nalajala4naresh/libkrun-go/krun"

	"github.com/nalajala4naresh/box/internal/agent"
	"github.com/nalajala4naresh/box/internal/config"
	"github.com/nalajala4naresh/box/internal/netstack"
	"github.com/nalajala4naresh/box/internal/sandbox"
	"github.com/nalajala4naresh/box/internal/store"
)

// Main runs the VM for sandbox name. It only returns on a setup error.
func Main(name string) error {
	// libkrun's VMM threads and the network stack share this process;
	// keep the entering goroutine on its own OS thread.
	runtime.LockOSThread()

	st, err := store.Open()
	if err != nil {
		return err
	}
	spec, err := sandbox.LoadSpec(st, name)
	if err != nil {
		return err
	}
	secrets := readSecrets()

	logger, err := netstack.OpenLogger(filepath.Join(sandbox.LogsDir(st, name), "system.log"))
	if err != nil {
		return err
	}
	logger.Infof("sandbox %s starting (cpus=%d memory=%dMiB)", name, spec.CPUs, spec.MaxMem)
	ca, err := netstack.LoadOrCreateCA(st.CADir())
	if err != nil {
		return fmt.Errorf("box CA: %w", err)
	}

	vmEnd, netEnd, err := netstack.SocketPair()
	if err != nil {
		return fmt.Errorf("network socket pair: %w", err)
	}
	network, err := netstack.New(netstack.Config{
		Policy:      spec.Policy,
		Secrets:     secrets,
		Ports:       spec.Ports,
		CA:          ca,
		Placeholder: config.SecretPlaceholder,
		Log:         logger,
	}, netEnd)
	if err != nil {
		return err
	}
	if err := serveControl(sandbox.ControlSocket(st, name), network, logger); err != nil {
		return err
	}

	if err := krun.SetLogLevel(krun.LogLevelWarn); err != nil {
		return err
	}
	ctx, err := krun.CreateContext()
	if err != nil {
		return fmt.Errorf("libkrun context: %w", err)
	}
	cpus := spec.CPUs
	if max, err := krun.GetMaxVCPUs(); err == nil && max > 0 && int(cpus) > max {
		cpus = uint8(max)
	}
	steps := []struct {
		what string
		err  func() error
	}{
		// The memory ceiling is the VM's RAM; the hypervisor only backs
		// pages the guest touches.
		{"vm config", func() error { return ctx.SetVMConfig(krun.VMConfig{NumVCPUs: cpus, RAMMiB: spec.MaxMem}) }},
		{"root", func() error { return ctx.SetRoot(sandbox.RootfsPath(st, name)) }},
		{"network", func() error {
			return ctx.AddNetUnixGram(krun.NetUnixConfig{FD: vmEnd, MAC: netstack.GuestMAC})
		}},
		{"agent vsock", func() error {
			return ctx.AddVsockPort(krun.VsockPortConfig{Port: agent.VsockPort, Path: sandbox.AgentSocket(st, name), Listen: true})
		}},
		{"workdir", func() error { return ctx.SetWorkdir("/") }},
		{"exec", func() error {
			// Kernel command line space is tight on aarch64: keep init's
			// environment minimal; commands get theirs from the agent.
			return ctx.SetExec(krun.ExecConfig{
				Path: agent.AgentPath,
				Args: []string{},
				Env:  []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=xterm-256color"},
			})
		}},
	}
	for i, vol := range spec.Volumes {
		vol, tag := vol, sandbox.VolumeTag(i)
		steps = append(steps, struct {
			what string
			err  func() error
		}{"volume " + vol.Guest, func() error { return ctx.AddVirtioFS(krun.VirtioFSConfig{Tag: tag, Path: vol.Host}) }})
	}
	for _, step := range steps {
		if err := step.err(); err != nil {
			if errors.Is(err, errNoSys) && step.what == "network" {
				return fmt.Errorf("libkrun %s: %w (build box with -tags krun_net against a libkrun built with NET=1)", step.what, err)
			}
			return fmt.Errorf("libkrun %s: %w", step.what, err)
		}
	}
	if err := os.WriteFile(filepath.Join(st.RunDir(name), "vm.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return err
	}
	logger.Infof("sandbox %s entering vm", name)
	err = ctx.StartEnter()
	// Only reached when libkrun refused to start.
	return fmt.Errorf("libkrun start: %w", err)
}

// readSecrets takes the live secret values the parent wrote to fd 3. They
// never touch the disk.
func readSecrets() []netstack.Secret {
	f := os.NewFile(3, "secrets")
	if f == nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil || len(data) == 0 {
		return nil
	}
	var secrets []netstack.Secret
	json.Unmarshal(data, &secrets)
	return secrets
}

func serveControl(path string, network *netstack.Network, logger *netstack.Logger) error {
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	os.Chmod(path, 0o600)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req sandbox.ControlRequest
				if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
					return
				}
				reply := sandbox.ControlReply{OK: true}
				switch req.Op {
				case "ping":
				case "secrets":
					network.SetSecrets(req.Secrets)
					logger.Infof("secret values rotated (%d live)", len(req.Secrets))
				default:
					reply = sandbox.ControlReply{Error: "unknown op " + req.Op}
				}
				json.NewEncoder(conn).Encode(reply)
			}()
		}
	}()
	return nil
}
