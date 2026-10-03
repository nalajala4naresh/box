//go:build linux

// wrap-agent is the guest half of wrap. libkrun's init runs it as the VM
// workload; it applies the boot configuration the host wrote into the
// rootfs, then serves exec and file operations over vsock until the host
// asks it to shut down. When it exits, init syncs and powers the VM off.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/nalajala4naresh/box/internal/agent"
	"github.com/nalajala4naresh/box/internal/agent/server"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("wrap-agent: ")
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(agent.Version)
		return
	}
	boot, err := readBoot(agent.BootPath)
	if err != nil {
		log.Printf("boot config: %v", err)
	}
	setup(boot)
	if err := serve(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func readBoot(path string) (agent.Boot, error) {
	var boot agent.Boot
	data, err := os.ReadFile(path)
	if err != nil {
		return boot, err
	}
	return boot, json.Unmarshal(data, &boot)
}

// setup applies every boot step it can; a failed step is logged, not fatal,
// so the host can still connect and see what went wrong.
func setup(boot agent.Boot) {
	step := func(name string, err error) {
		if err != nil {
			log.Printf("%s: %v", name, err)
		}
	}
	step("mount /run", mountTmpfs("/run", "mode=0755"))
	step("mount /tmp", mountTmpfs("/tmp", "mode=1777"))
	for _, m := range boot.Mounts {
		step("mount "+m.Path, mountVirtiofs(m))
	}
	if boot.Hostname != "" {
		step("hostname", setHostname(boot.Hostname))
	}
	if boot.Net != nil {
		step("network", setupNetwork(*boot.Net))
	}
	step("disable ipv6", disableIPv6())
	if boot.Timezone != "" {
		step("timezone", setTimezone(boot.Timezone))
	}
	if boot.CAPath != "" {
		step("trust ca", trustCA(boot.CAPath))
	}
}

func isMountPoint(path string) bool {
	var st, parent unix.Stat_t
	if unix.Lstat(path, &st) != nil || unix.Lstat(filepath.Dir(path), &parent) != nil {
		return false
	}
	return st.Dev != parent.Dev
}

func mountTmpfs(path, opts string) error {
	if isMountPoint(path) {
		return nil
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	return unix.Mount("tmpfs", path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_RELATIME, opts)
}

func mountVirtiofs(m agent.Mount) error {
	if err := os.MkdirAll(m.Path, 0o755); err != nil {
		return err
	}
	var flags uintptr = unix.MS_RELATIME
	if m.ReadOnly {
		flags |= unix.MS_RDONLY
	}
	return unix.Mount(m.Tag, m.Path, "virtiofs", flags, "")
}

func setHostname(name string) error {
	if err := unix.Sethostname([]byte(name)); err != nil {
		return err
	}
	hosts, err := os.ReadFile("/etc/hosts")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(string(hosts), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "127.0.1.1" && fields[1] == name {
			return nil
		}
	}
	var out bytes.Buffer
	for _, line := range strings.Split(strings.TrimRight(string(hosts), "\n"), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "127.0.1.1") && line != "" {
			out.WriteString(line + "\n")
		}
	}
	if !bytes.Contains(out.Bytes(), []byte("localhost")) {
		out.WriteString("127.0.0.1 localhost\n")
	}
	out.WriteString("127.0.1.1 " + name + "\n")
	return os.WriteFile("/etc/hosts", out.Bytes(), 0o644)
}

func setupNetwork(cfg agent.Net) error {
	link, err := netlink.LinkByName(cfg.Iface)
	if err != nil {
		return fmt.Errorf("find %s: %w", cfg.Iface, err)
	}
	if cfg.MTU > 0 {
		if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
	}
	addr, err := netlink.ParseAddr(cfg.Address)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("add address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	gw := net.ParseIP(cfg.Gateway)
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw}); err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	// A dangling stub symlink (systemd-resolved images) would swallow the
	// write; replace whatever is there.
	_ = os.Remove("/etc/resolv.conf")
	return os.WriteFile("/etc/resolv.conf", []byte("nameserver "+cfg.DNS+"\n"), 0o644)
}

// disableIPv6 keeps every runtime on IPv4: the userspace network only
// routes IPv4, and dual-stack names would otherwise try v6 first.
func disableIPv6() error {
	var errs []error
	for _, path := range []string{
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
	} {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func setTimezone(name string) error {
	zone := filepath.Join("/usr/share/zoneinfo", filepath.Clean("/"+name))
	if _, err := os.Stat(zone); err != nil {
		return nil
	}
	if current, err := os.Readlink("/etc/localtime"); err == nil && current == zone {
		return nil
	}
	_ = os.Remove("/etc/localtime")
	return os.Symlink(zone, "/etc/localtime")
}

// trustCA installs wrap's interception CA into the distro trust store,
// rebuilding the bundle only when the anchor changed.
func trustCA(path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	stores := []struct {
		dir    string
		anchor string
		update []string
	}{
		{"/etc/ca-certificates/trust-source/anchors", "wrap-ca.crt", []string{"update-ca-trust", "extract"}},
		{"/usr/local/share/ca-certificates", "wrap-ca.crt", []string{"update-ca-certificates"}},
		{"/etc/pki/ca-trust/source/anchors", "wrap-ca.crt", []string{"update-ca-trust", "extract"}},
	}
	for _, store := range stores {
		if info, err := os.Stat(store.dir); err != nil || !info.IsDir() {
			continue
		}
		anchor := filepath.Join(store.dir, store.anchor)
		if current, err := os.ReadFile(anchor); err == nil && bytes.Equal(current, pem) {
			return nil
		}
		if err := os.WriteFile(anchor, pem, 0o644); err != nil {
			return err
		}
		updater, err := exec.LookPath(store.update[0])
		if err != nil {
			return fmt.Errorf("%s not found", store.update[0])
		}
		cmd := exec.Command(updater, store.update[1:]...)
		cmd.Env = []string{"PATH=" + server.DefaultPath}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", store.update[0], err, bytes.TrimSpace(out))
		}
		return nil
	}
	return nil
}

func serve() error {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: agent.VsockPort}); err != nil {
		return fmt.Errorf("vsock bind: %w", err)
	}
	if err := unix.Listen(fd, 128); err != nil {
		return fmt.Errorf("vsock listen: %w", err)
	}
	for {
		nfd, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ECONNABORTED) {
				continue
			}
			return fmt.Errorf("vsock accept: %w", err)
		}
		if err := unix.SetNonblock(nfd, true); err != nil {
			unix.Close(nfd)
			continue
		}
		go server.Handle(os.NewFile(uintptr(nfd), "vsock"))
	}
}
