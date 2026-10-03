package app

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/nalajala4naresh/box/internal/config"
	"github.com/nalajala4naresh/box/internal/netstack"
	"github.com/nalajala4naresh/box/internal/sandbox"
	"github.com/nalajala4naresh/box/internal/shell"
	"github.com/nalajala4naresh/box/internal/store"
	"github.com/nalajala4naresh/box/internal/ui"
)

type vmResourcesT struct {
	cpus      uint8
	memory    uint32
	memoryMax uint32
}

// baseLayoutIdentity is recorded on each session as baseLayoutLabel.
//
// The snapshot name only encodes the image reference and layer scripts, so
// it survives a --rebuild that pulled a newer tag; the snapshot digest does
// not, which makes every workspace's session notice a refreshed base and
// recreate itself. Published ports and everything else baked at session
// creation (network allow/deny, secret structure, agent host-copies) fold
// in too, so config drift never leaves a stale policy or copy behind.
// Rotated secret values are the exception: they converge live. Guest env,
// the IPv4 preference, and cpus/memory apply on every entry and need no
// recreate.
func baseLayoutIdentity(st *store.Store, baseSnapshot string, cfg config.Config, secrets config.ResolvedSecrets) (string, error) {
	snap, err := sandbox.OpenSnapshot(st, baseSnapshot)
	if err != nil {
		return "", fmt.Errorf("open base snapshot %s: %w", baseSnapshot, err)
	}
	identity := baseSnapshot + "@" + snap.Digest
	if len(cfg.Network.Ports) > 0 {
		ports := make([]string, 0, len(cfg.Network.Ports))
		for _, p := range cfg.Network.Ports {
			ports = append(ports, fmt.Sprintf("%d:%d", p.Host, p.Guest))
		}
		identity += ";ports=" + strings.Join(ports, ",")
	}
	identity += ";session=" + sessionConfigDigest(cfg, secrets)
	return identity, nil
}

func sessionConfigDigest(cfg config.Config, secrets config.ResolvedSecrets) string {
	digest := sha256.New()
	field := func(tag string, values ...string) {
		digest.Write([]byte(tag))
		digest.Write([]byte{0})
		for _, value := range values {
			digest.Write([]byte(value))
			digest.Write([]byte{0})
		}
	}
	field("allow-everything", strconv.FormatBool(cfg.Network.AllowEverything))
	field("allow", cfg.Network.Allow...)
	field("deny", cfg.Network.Deny...)
	for _, secret := range secrets.Found {
		field("secret-env", secret.Env)
		var headers []string
		for _, h := range secret.SortedHeaders() {
			headers = append(headers, h[0], h[1])
		}
		field("secret-headers", headers...)
		field("secret-hosts", secret.Hosts...)
	}
	field("skipped", secrets.Skipped...)
	for _, agent := range cfg.Agents {
		hostCopy, guest := "", ""
		if agent.HostCopy != nil {
			hostCopy = *agent.HostCopy
		}
		if agent.Guest != nil {
			guest = *agent.Guest
		}
		field("agent", agent.Name, hostCopy, guest)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

// secretValuesDigest hashes live secret names and values. A mismatch with
// the session label means values rotated; values only ever appear as hash
// material, never as label text.
func secretValuesDigest(secrets config.ResolvedSecrets) string {
	digest := sha256.New()
	for _, secret := range secrets.Found {
		digest.Write([]byte(secret.Env))
		digest.Write([]byte{0})
		digest.Write([]byte(secret.Value))
		digest.Write([]byte{0})
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

// rotateChangedSecrets converges changed secret values into a reused
// session without recreating it. Structural drift already forced a
// recreate via the layout digest, so only material changes here. A failure
// leaves the session on its previous credential.
func rotateChangedSecrets(sb *sandbox.Sandbox, current string, secrets config.ResolvedSecrets) error {
	digest := secretValuesDigest(secrets)
	if current == digest {
		return nil
	}
	if err := sb.UpdateSecrets(liveSecrets(secrets)); err != nil {
		return err
	}
	return sb.SetLabel(secretValuesLabel, digest)
}

func secretDecls(secrets config.ResolvedSecrets) []sandbox.SecretDecl {
	var decls []sandbox.SecretDecl
	for _, secret := range secrets.Found {
		decl := sandbox.SecretDecl{Env: secret.Env, Hosts: secret.Hosts}
		for _, h := range secret.SortedHeaders() {
			decl.Headers = append(decl.Headers, h[0])
		}
		decls = append(decls, decl)
	}
	return decls
}

func liveSecrets(secrets config.ResolvedSecrets) []netstack.Secret {
	var out []netstack.Secret
	for _, secret := range secrets.Found {
		s := netstack.Secret{Env: secret.Env, Value: secret.Value, Hosts: secret.Hosts}
		for _, h := range secret.SortedHeaders() {
			s.Headers = append(s.Headers, h[0])
		}
		out = append(out, s)
	}
	return out
}

func (a *App) openOrCreateSession(cli CLI, cfg config.Config, resources vmResourcesT, baseSnapshot, baseLayout, name, cwd string, secrets config.ResolvedSecrets) (*sandbox.Sandbox, ui.CrossingKind, error) {
	live := a.ui.StartTask("session")
	defer live.Close()
	var kind ui.CrossingKind
	if cli.Reset {
		a.ui.SettingUpProject()
		live.Phase("replacing vm")
		kind = ui.Reset
	} else if existing, err := sandbox.Get(a.store, name); err == nil {
		if existing.Spec.Labels[baseLayoutLabel] != baseLayout {
			a.ui.SettingUpProject()
			live.Phase("updating base layout")
			kind = ui.Reset
		} else {
			live.Phase("enforcing vm resources")
			if err := enforceSessionResources(existing, resources, liveSecrets(secrets)); err != nil {
				live.Fail("resize failed")
				return nil, kind, err
			}
			live.Phase("resuming vm")
			if err := resumeSession(existing, liveSecrets(secrets)); err != nil {
				live.Fail("resume failed")
				return nil, kind, err
			}
			if err := rotateChangedSecrets(existing, existing.Spec.Labels[secretValuesLabel], secrets); err != nil {
				a.ui.Warn(fmt.Sprintf("secret rotation failed: %v", err))
			}
			live.Done()
			return existing, ui.Reused, nil
		}
	} else {
		a.ui.SettingUpProject()
		kind = ui.New
	}

	live.Phase("cloning shared snapshot")
	sb, err := waitWithLive(live, func(context.Context) (*sandbox.Sandbox, error) {
		return createSession(a.store, cfg, resources, baseSnapshot, baseLayout, name, cwd, secrets)
	})
	if err != nil {
		live.Fail("create failed")
		return nil, kind, err
	}
	live.Done()
	return sb, kind, nil
}

func enforceSessionResources(sb *sandbox.Sandbox, desired vmResourcesT, secrets []netstack.Secret) error {
	if sb.Spec.CPUs == desired.cpus && sb.Spec.Memory == desired.memory && sb.Spec.MaxMem == desired.memoryMax {
		return nil
	}
	if err := sb.SetResources(desired.cpus, desired.memory, desired.memoryMax, secrets); err != nil {
		return fmt.Errorf("enforce session resources %s: %w", sb.Name(), err)
	}
	return nil
}

// drainGrace bounds the wait for a previous invocation's graceful
// shutdown.
const drainGrace = 20 * time.Second

// resumeSession connects to a running VM or boots a stopped one. box
// requests a graceful stop and returns without waiting, so a follow-up
// invocation can find the previous VM still draining: wait for it to
// settle and start fresh.
func resumeSession(sb *sandbox.Sandbox, secrets []netstack.Secret) error {
	if sb.Status() == sandbox.Draining {
		if err := sb.WaitStopped(drainGrace); err != nil {
			return fmt.Errorf("previous session did not finish shutting down: %w", err)
		}
	}
	if sb.Status() == sandbox.Running {
		if err := sb.Connect(); err == nil {
			return nil
		}
		// A wedged VM: restart it.
		if err := sb.Stop(); err != nil {
			return fmt.Errorf("connect existing sandbox: %w", err)
		}
	}
	if err := sb.Start(secrets); err != nil {
		return fmt.Errorf("start existing sandbox: %w", err)
	}
	return nil
}

type hostIdentityT struct{ uid, gid uint32 }

func hostIdentity(cwd string) (hostIdentityT, error) {
	info, err := os.Stat(cwd)
	if err != nil {
		return hostIdentityT{}, fmt.Errorf("stat workspace %s: %w", cwd, err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return hostIdentityT{uid: st.Uid, gid: uint32(st.Gid)}, nil
}

// guestUserFor keeps root in the guest only for a root-owned workspace.
func guestUserFor(id hostIdentityT) string {
	if id.uid == 0 {
		return guestRoot
	}
	return GuestUser
}

func guestHomeFor(id hostIdentityT) string {
	if id.uid == 0 {
		return "/root"
	}
	return GuestHome
}

func createSession(st *store.Store, cfg config.Config, resources vmResourcesT, baseSnapshot, baseLayout, name, cwd string, secrets config.ResolvedSecrets) (*sandbox.Sandbox, error) {
	identity, err := hostIdentity(cwd)
	if err != nil {
		return nil, err
	}
	user := guestUserFor(identity)
	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}
	spec := sandbox.Spec{
		Name:     name,
		CPUs:     resources.cpus,
		Memory:   resources.memory,
		MaxMem:   resources.memoryMax,
		Shell:    "/bin/zsh",
		Workdir:  Workspace,
		Hostname: workspaceBase(cwd),
		User:     user,
		Labels: map[string]string{
			baseLayoutLabel:   baseLayout,
			secretValuesLabel: secretValuesDigest(secrets),
		},
		Env: []sandbox.EnvVar{
			{Key: "HOME", Value: guestHomeFor(identity)},
			{Key: "USER", Value: user},
			{Key: "TERM", Value: term},
			{Key: "OUTER_HOSTNAME", Value: outerHostname()},
			{Key: "OUTER_PWD", Value: cwd},
			{Key: "OUTER_PWD_BASE", Value: workspaceBase(cwd)},
		},
		// Literal host ownership: with the guest user realigned to the
		// host owner, the share is writable without chown or xattrs.
		Volumes:  []sandbox.Volume{{Host: cwd, Guest: Workspace}},
		Policy:   sessionPolicy(cfg, secrets),
		Secrets:  secretDecls(secrets),
		Timezone: hostTimezone(),
	}
	for _, key := range sortedEnvKeys(cfg.Env) {
		spec.Env = append(spec.Env, sandbox.EnvVar{Key: key, Value: cfg.Env[key]})
	}
	// Published to the host loopback only (e.g. the desktop image's noVNC).
	for _, port := range cfg.Network.Ports {
		spec.Ports = append(spec.Ports, netstack.PortForward{Host: port.Host, Guest: port.Guest})
	}
	sb, err := sandbox.Create(st, spec, sandbox.Source{Snapshot: baseSnapshot}, liveSecrets(secrets))
	if err != nil {
		return nil, fmt.Errorf("create session sandbox: %w", err)
	}
	if user == GuestUser {
		if err := alignGuestIdentity(sb, identity); err != nil {
			return nil, err
		}
	}
	return sb, nil
}

// sessionPolicy: only live secrets whitelist their hosts; skipped
// optionals add nothing, and network.deny already won.
func sessionPolicy(cfg config.Config, secrets config.ResolvedSecrets) netstack.Policy {
	return netstack.Policy{
		AllowEverything: cfg.Network.AllowEverything,
		Allow:           config.EffectiveAllowHosts(cfg, secrets),
		Deny:            append([]string(nil), cfg.Network.Deny...),
	}
}

func sortedEnvKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// alignGuestIdentity realigns the guest `user` uid/gid with the host owner
// of the workspace. The share exposes literal host ownership, so matching
// ids is what makes it writable for the unprivileged session.
func alignGuestIdentity(sb *sandbox.Sandbox, id hostIdentityT) error {
	script := alignScript(id)
	out, err := rootShell(sb, script)
	if err != nil {
		return fmt.Errorf("align guest user identity: %w", err)
	}
	if !out.Success() {
		return fmt.Errorf("align guest user identity exited %d: %s", out.Code, strings.TrimSpace(string(out.Stderr)))
	}
	return nil
}

// alignScript renders the uid/gid realignment run as guest root.
func alignScript(id hostIdentityT) string {
	return fmt.Sprintf("set -eu\n"+
		"uid=%d; gid=%d\n"+
		"cur_gid=$(getent group %[3]s | cut -d: -f3)\n"+
		"if [ \"$cur_gid\" != \"$gid\" ]; then\n"+
		"  if getent group \"$gid\" >/dev/null; then groupmod -o -g \"$gid\" %[3]s; else groupmod -g \"$gid\" %[3]s; fi\n"+
		"fi\n"+
		"cur_uid=$(id -u %[3]s)\n"+
		"if [ \"$cur_uid\" != \"$uid\" ]; then usermod -o -u \"$uid\" -g \"$gid\" %[3]s; fi\n"+
		"# Everything `user` owns follows the id change: home and the toolchain.\n"+
		"# -xdev keeps it off the workspace share, which keeps host ownership.\n"+
		"if [ \"$cur_uid\" != \"$uid\" ] || [ \"$cur_gid\" != \"$gid\" ]; then\n"+
		"  find %[4]s %[5]s -xdev -exec chown -h \"$uid:$gid\" {} +\n"+
		"fi\n", id.uid, id.gid, GuestUser, shell.Quote(GuestHome), shell.Quote("/opt/mise"))
}

// rootShell runs a script as guest root regardless of the default user.
func rootShell(sb *sandbox.Sandbox, script string) (sandbox.Output, error) {
	return sb.Exec(sandbox.ExecOptions{
		Argv: []string{"/bin/sh", "-c", script},
		User: guestRoot,
		Env:  []sandbox.EnvVar{{Key: "HOME", Value: "/root"}, {Key: "USER", Value: guestRoot}},
		Cwd:  "/",
	})
}

// ipv6DisableScript: guest IPv6 has no upstream, and dual-stack names
// would try v6 first. The agent applies it at boot too; sessions reapply
// it on every entry for parity with images that re-enable it.
func ipv6DisableScript() string {
	return "set -eu\necho 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6\n" +
		"echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6\n"
}

func ensureIPv4Egress(sb *sandbox.Sandbox) error {
	out, err := rootShell(sb, "[ -d /proc/sys/net/ipv6 ] || exit 0\n"+ipv6DisableScript())
	if err != nil {
		return fmt.Errorf("disable guest IPv6 egress: %w", err)
	}
	if !out.Success() {
		return fmt.Errorf("disable guest IPv6 egress exited %d: %s", out.Code, strings.TrimSpace(string(out.Stderr)))
	}
	return nil
}

func (a *App) applySessionConfig(sb *sandbox.Sandbox, cfg config.Config, copies []config.ResolvedHostCopy) error {
	live := a.ui.StartTask("session")
	defer live.Close()
	live.Phase("disabling IPv6 egress")
	if err := ensureIPv4Egress(sb); err != nil {
		live.Fail("network setup failed")
		return err
	}
	if marker := hostCopyMarker(copies); marker != "" {
		exists, err := sb.Exists(marker)
		if err != nil {
			return fmt.Errorf("check imported host state: %w", err)
		}
		if !exists {
			live.Phase("copying host state")
			if err := copyHostState(sb, copies); err != nil {
				live.Fail("host copy failed")
				return err
			}
			out, err := rootShell(sb, "mkdir -p /var/lib/box && : > "+shell.Quote(marker))
			if err != nil {
				return fmt.Errorf("mark imported host state: %w", err)
			}
			if !out.Success() {
				live.Fail("host copy marker failed")
				return errors.New("mark imported host state failed")
			}
		}
	}
	live.Phase("installing agent shims")
	if err := installAgentShims(sb, cfg); err != nil {
		live.Fail("shim install failed")
		return err
	}
	live.Done()
	return nil
}

func hostCopyMarker(copies []config.ResolvedHostCopy) string {
	if len(copies) == 0 {
		return ""
	}
	digest := sha256.New()
	for _, c := range copies {
		digest.Write([]byte(c.Agent))
		digest.Write([]byte{0})
		digest.Write([]byte(c.Host))
		digest.Write([]byte{0})
		digest.Write([]byte(c.Guest))
		digest.Write([]byte{0})
	}
	sum := digest.Sum(nil)
	return fmt.Sprintf("/var/lib/box/host-copy-%02x%02x%02x%02x", sum[0], sum[1], sum[2], sum[3])
}

func copyHostState(sb *sandbox.Sandbox, copies []config.ResolvedHostCopy) error {
	out, err := rootShell(sb, "set -eu\nmkdir -p /var/lib/box\nrm -f /var/lib/box/.host-copy.tar\n")
	if err != nil || !out.Success() {
		return fmt.Errorf("prepare host-copy staging failed: %v %s", err, strings.TrimSpace(string(out.Stderr)))
	}
	for _, c := range copies {
		parent := path.Dir(c.Guest)
		if out, err := rootShell(sb, "mkdir -p "+shell.Quote(parent)); err != nil || !out.Success() {
			return fmt.Errorf("prepare agent %s host-copy failed", c.Agent)
		}
		info, err := os.Stat(c.Host)
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			if err := sb.CopyFromHost(c.Host, c.Guest); err != nil {
				return fmt.Errorf("copy agent %s host file: %w", c.Agent, err)
			}
			if out, err := rootShell(sb, chownToGuestUser(c.Guest)); err != nil || !out.Success() {
				return fmt.Errorf("chown agent %s host file failed", c.Agent)
			}
			continue
		}
		if !info.IsDir() {
			return fmt.Errorf("agent %s host-copy is not a regular file or directory: %s", c.Agent, c.Host)
		}
		archive, err := os.CreateTemp("", "box-host-copy-*.tar")
		if err != nil {
			return err
		}
		archivePath := archive.Name()
		err = tarDirectory(archive, c.Host)
		archive.Close()
		if err != nil {
			os.Remove(archivePath)
			return fmt.Errorf("archive agent %s host-copy: %w", c.Agent, err)
		}
		const guestArchive = "/var/lib/box/.host-copy.tar"
		err = sb.CopyFromHost(archivePath, guestArchive)
		os.Remove(archivePath)
		if err != nil {
			return fmt.Errorf("transfer agent %s host-copy: %w", c.Agent, err)
		}
		script := fmt.Sprintf("set -eu\nrm -rf %[1]s\nmkdir -p %[1]s\ntar -xf %[2]s -C %[1]s\nrm -f %[2]s\n%[3]s",
			shell.Quote(c.Guest), shell.Quote(guestArchive), chownToGuestUser(c.Guest))
		out, err := rootShell(sb, script)
		if err != nil {
			return fmt.Errorf("extract agent %s host-copy: %w", c.Agent, err)
		}
		if !out.Success() {
			return fmt.Errorf("extract agent %s host-copy exited %d: %s", c.Agent, out.Code, strings.TrimSpace(string(out.Stderr)))
		}
	}
	return nil
}

// tarDirectory archives dir's contents, skipping anything unreadable or
// changing underneath (like `tar --ignore-failed-read`).
func tarDirectory(w io.Writer, dir string) error {
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return nil
			}
		}
		if !info.Mode().IsRegular() && !info.IsDir() && link == "" {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return nil
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		hdr.Uname, hdr.Gname, hdr.Uid, hdr.Gid = "", "", 0, 0
		if info.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return nil
			}
			defer f.Close()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			_, err = io.CopyN(tw, f, hdr.Size)
			if err != nil {
				return err
			}
			return nil
		}
		return tw.WriteHeader(hdr)
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// chownToGuestUser: imported state and its parents (up to, not including,
// the home directory) must be owned by the session user; the agent copies
// files in as root.
func chownToGuestUser(guest string) string {
	script := fmt.Sprintf("chown -R %s:%s %s\n", GuestUser, GuestUser, shell.Quote(guest))
	for dir := path.Dir(guest); dir != "/" && dir != GuestHome && strings.HasPrefix(dir, GuestHome); dir = path.Dir(dir) {
		script += fmt.Sprintf("chown %s:%s %s\n", GuestUser, GuestUser, shell.Quote(dir))
	}
	return script
}

func installAgentShims(sb *sandbox.Sandbox, cfg config.Config) error {
	if len(cfg.Agents) == 0 {
		return nil
	}
	script := "set -eu\nmkdir -p /usr/local/bin\n"
	for _, agent := range cfg.Agents {
		for _, c := range agent.Name {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return fmt.Errorf("invalid agent shim name: %s", agent.Name)
			}
		}
		// Version-less: resolve through the pinned global config so the
		// shim never triggers a runtime install.
		pkg, err := miseInstallPackage(agent.Package)
		if err != nil {
			return err
		}
		pkg, _, _ = strings.Cut(pkg, "@")
		target := "/usr/local/bin/" + agent.Name
		script += fmt.Sprintf("cat > %s <<'BOX_SHIM'\n#!/bin/sh\nexec mise exec %s -- %s \"$@\"\nBOX_SHIM\nchmod 0755 %s\n",
			shell.Quote(target), shell.Quote(pkg), shell.Quote(agent.Name), shell.Quote(target))
	}
	out, err := rootShell(sb, script)
	if err != nil {
		return fmt.Errorf("install agent shims: %w", err)
	}
	if !out.Success() {
		return fmt.Errorf("install agent shims exited %d: %s", out.Code, out.Stderr)
	}
	return nil
}

func exposureReport(cfg config.Config, secrets config.ResolvedSecrets, copies []config.ResolvedHostCopy, sources []config.Source) ui.ExposureReport {
	report := ui.ExposureReport{
		AllowEverything: cfg.Network.AllowEverything,
		Allow:           config.EffectiveAllowHosts(cfg, secrets),
		Deny:            cfg.Network.Deny,
		Skipped:         secrets.Skipped,
	}
	for _, source := range sources {
		report.Sources = append(report.Sources, source.Label())
	}
	for _, secret := range secrets.Found {
		report.Secrets = append(report.Secrets, ui.ExposureSecret{Env: secret.Env, Headers: secret.SortedHeaders(), Hosts: secret.Hosts})
	}
	for _, port := range cfg.Network.Ports {
		if port.Host == port.Guest {
			report.Ports = append(report.Ports, strconv.Itoa(int(port.Host)))
		} else {
			report.Ports = append(report.Ports, fmt.Sprintf("%d:%d", port.Host, port.Guest))
		}
	}
	for _, c := range copies {
		report.Copies = append(report.Copies, [2]string{c.Agent, c.Guest})
	}
	for _, key := range sortedEnvKeys(cfg.Env) {
		report.Env = append(report.Env, [2]string{key, cfg.Env[key]})
	}
	return report
}

func enterSession(u *ui.UI, cfg config.Config, sb *sandbox.Sandbox, secrets config.ResolvedSecrets, command []string) (int, error) {
	if secretsNeedGitHeader(command, secrets) {
		if name, value, ok := githubExtraheader(secrets); ok {
			sb.Shell(fmt.Sprintf("git config --global http.https://github.com/.extraheader \"%s: %s\"", name, value), sandbox.ExecOptions{})
		}
	}
	argv := guestCommand(cfg, command)
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		u.Attached()
		code, err := sb.Attach(sandbox.ExecOptions{Argv: argv, Cwd: Workspace})
		if err != nil {
			return 1, fmt.Errorf("attach session: %w", err)
		}
		if code < 0 {
			return 0, nil
		}
		return code & 0xff, nil
	}
	opts := sandbox.ExecOptions{Argv: argv, Cwd: Workspace}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		opts.Stdin = os.Stdin
	}
	events, _, err := sb.Stream(opts)
	if err != nil {
		return 1, fmt.Errorf("exec session: %w", err)
	}
	for event := range events {
		os.Stdout.Write(event.Stdout)
		os.Stderr.Write(event.Stderr)
		if event.Err != nil {
			return 1, fmt.Errorf("exec session: %w", event.Err)
		}
		if event.Exited {
			return event.Code & 0xff, nil
		}
	}
	return 1, errors.New("exec session: no exit status")
}

func guestExports(cfg config.Config) string {
	out := GuestPathExports()
	for _, key := range sortedEnvKeys(cfg.Env) {
		out += "; export " + key + "=" + shell.Quote(cfg.Env[key])
	}
	// Session shells get the same first-thing GitHub authentication as
	// build stages, so runtime mise installs authenticate too.
	return out + "; " + MiseGithubAuthSnippet()
}

func guestCommand(cfg config.Config, command []string) []string {
	exports := guestExports(cfg)
	if len(command) == 0 {
		return []string{"/bin/zsh", "-l", "-c", exports + "; exec /bin/zsh -l"}
	}
	return []string{"/bin/zsh", "-l", "-c", exports + "; exec " + shell.Join(command)}
}

// githubExtraheader: the first live secret declaring an Authorization
// header for exactly github.com provides git's http.extraheader. The value
// references a guest env var, so the shell expands it to the stand-in and
// the network substitutes the real token on the wire.
func githubExtraheader(secrets config.ResolvedSecrets) (string, string, bool) {
	for _, secret := range secrets.Found {
		covers := false
		for _, host := range secret.Hosts {
			if host == "github.com" {
				covers = true
				break
			}
		}
		if !covers {
			continue
		}
		for _, h := range secret.SortedHeaders() {
			if strings.EqualFold(h[0], "authorization") {
				return h[0], h[1], true
			}
		}
	}
	return "", "", false
}

func secretsNeedGitHeader(command []string, secrets config.ResolvedSecrets) bool {
	_, _, ok := githubExtraheader(secrets)
	return (len(command) == 0 || command[0] != "true") && ok
}

// SandboxName derives a workspace's sandbox from its real path.
func SandboxName(cwd string) (string, error) {
	real, err := filepath.EvalSymlinks(cwd)
	if err == nil {
		real, err = filepath.Abs(real)
	}
	if err != nil {
		return "", fmt.Errorf("realpath %s: %w", cwd, err)
	}
	return sandboxNameFromReal(real), nil
}

func sandboxNameFromReal(real string) string {
	sum := sha256.Sum256([]byte(real))
	return fmt.Sprintf("box-%x", sum[:8])
}

func workspaceBase(cwd string) string {
	base := filepath.Base(cwd)
	if base == "/" || base == "." || base == "" {
		return "workspace"
	}
	return base
}

func outerHostname() string {
	if h := os.Getenv("HOSTNAME"); h != "" {
		return h
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return strings.TrimSuffix(h, ".local")
	}
	return "host"
}

// hostTimezone is the IANA name behind /etc/localtime.
func hostTimezone() string {
	if tz := os.Getenv("TZ"); tz != "" && !strings.HasPrefix(tz, ":") && !strings.HasPrefix(tz, "/") {
		return tz
	}
	target, err := os.Readlink("/etc/localtime")
	if err != nil {
		return ""
	}
	if _, zone, ok := strings.Cut(target, "zoneinfo/"); ok {
		return zone
	}
	return ""
}

func balloonMemory(boot, max uint32) (uint32, uint32) {
	max = maxU32(max, sessionMemoryMin)
	boot = minU32(maxU32(boot, sessionMemoryMin), max)
	return boot, max
}

func vmResources(cli CLI, cfg config.Config) (vmResourcesT, error) {
	cpus := cfg.Sandbox.CPUs
	if cli.CPUs != nil {
		cpus = *cli.CPUs
	}
	if cpus == 0 {
		return vmResourcesT{}, errors.New("VM CPU count must be greater than zero")
	}
	memory := cfg.Sandbox.Memory
	if cli.MemoryBoot != nil {
		memory = *cli.MemoryBoot
	}
	memoryMax := cfg.Sandbox.MemoryMax
	if cli.Memory != nil {
		memoryMax = *cli.Memory
	}
	memory, memoryMax = balloonMemory(memory, memoryMax)
	return vmResourcesT{cpus: cpus, memory: memory, memoryMax: memoryMax}, nil
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
