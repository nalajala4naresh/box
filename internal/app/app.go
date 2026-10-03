// Package app is box's command logic: layered base snapshots, one cached
// project VM per workspace, and the host → vm crossing.
package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nalajala4naresh/box/internal/config"
	"github.com/nalajala4naresh/box/internal/methods"
	"github.com/nalajala4naresh/box/internal/netstack"
	"github.com/nalajala4naresh/box/internal/sandbox"
	"github.com/nalajala4naresh/box/internal/store"
	"github.com/nalajala4naresh/box/internal/ui"
	"github.com/nalajala4naresh/box/resources"
)

const (
	// Workspace is the guest path of the bound project. It lives under the
	// guest user's home so shells and relative paths treat the project as
	// home; $HOME itself stays /home/user, keeping caches, dotfiles, and
	// host-copies outside the project.
	Workspace          = methods.Workspace
	baseSnapshotPrefix = "box-image"
	baseLayoutLabel    = "box.base-layout"
	secretValuesLabel  = "box.secret-values"
	sessionMemoryMin   = 4096
	// GuestUser is the unprivileged guest identity baked into the image
	// (passwordless sudo). Sessions run as it; only build plumbing runs as
	// root. Its uid/gid are realigned to the workspace owner at session
	// creation so the virtio-fs workspace is writable without chowning.
	GuestUser     = "user"
	GuestHome     = config.GuestHome
	guestRoot     = "root"
	miseDataDir   = "/opt/mise/data"
	miseConfigDir = "/opt/mise/config"
)

// guestPathDirs come first on every guest command's PATH, in order.
var guestPathDirs = []string{"/usr/local/bin", "$HOME/.local/bin", "/opt/mise/data/shims", "/opt/box/bin"}

// GuestPathExports is POSIX sh that prepends guestPathDirs to PATH, skipping
// any already present, so repeated application never stacks duplicates.
func GuestPathExports() string {
	var parts []string
	for i := len(guestPathDirs) - 1; i >= 0; i-- {
		dir := guestPathDirs[i]
		parts = append(parts, fmt.Sprintf(`case ":$PATH:" in *":%s:"*) ;; *) PATH="%s:$PATH" ;; esac`, dir, dir))
	}
	parts = append(parts, "export PATH")
	return strings.Join(parts, "; ")
}

// App carries one invocation's shared state.
type App struct {
	ui    *ui.UI
	store *store.Store
}

// Main runs box with the given arguments and returns the exit code.
func Main(args []string) int {
	code, err := run(args)
	if err != nil {
		if errors.Is(err, ErrHelp) {
			return 0
		}
		ui.Stderr().Fatal(err)
		return 1
	}
	return code
}

func run(args []string) (int, error) {
	cli, err := ParseCLI(args, func(text string) { fmt.Print(text) })
	if err != nil {
		if errors.Is(err, ErrHelp) {
			return 0, err
		}
		return 2, err
	}
	if cli.Skill {
		fmt.Print(resources.Skill)
		return 0, nil
	}

	var cwd string
	if cli.Target != "" {
		abs, err := filepath.Abs(cli.Target)
		if err == nil {
			abs, err = filepath.EvalSymlinks(abs)
		}
		if err != nil {
			return 1, fmt.Errorf("realpath %s: %w", cli.Target, err)
		}
		cwd = abs
	} else if cwd, err = os.Getwd(); err != nil {
		return 1, fmt.Errorf("current directory: %w", err)
	}
	explicit := cli.Config
	if explicit == "" {
		explicit = os.Getenv("BOX_CONFIG")
	}

	switch cli.Sub {
	case SubInit:
		path, err := config.InitWorkspace(cwd)
		if err != nil {
			return 1, err
		}
		fmt.Printf("wrote %s\n", path)
		return 0, nil
	case SubConfig:
		loaded, err := config.LoadFull(cwd, explicit)
		if err != nil {
			return 1, err
		}
		text, err := config.ToYAML(loaded.Config)
		if err != nil {
			return 1, err
		}
		fmt.Print(text)
		return 0, nil
	case SubAllow:
		return runAllow(cwd, cli.AllowHost, cli.AllowGlobal)
	case SubLog:
		return runLog(cwd, explicit, cli.LogTail, cli.LogFollow)
	}

	if method, ok := fastMethod(cli.Rebuild, cli.Reset, cli.Command); ok {
		sb, err := connectExisting(cwd, explicit)
		if err != nil {
			return 1, err
		}
		return methods.Run(sb, method, GuestPathExports())
	}

	loaded, err := config.LoadFull(cwd, explicit)
	if err != nil {
		return 1, err
	}
	cfg := loaded.Config
	// One-entry override: flip the in-memory flag so the session digest,
	// policy, and exposure report all follow, without writing any file.
	if cli.NetworkAllowEverything {
		cfg.Network.AllowEverything = true
	}
	if err := rejectBareUnknownCommand(cli, cfg); err != nil {
		return 1, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return 1, fmt.Errorf("home directory: %w", err)
	}
	secrets, err := config.ResolveSecrets(cfg)
	if err != nil {
		return 1, err
	}
	hostCopies, err := config.ResolveHostCopies(cfg, home)
	if err != nil {
		return 1, err
	}
	resources, err := vmResources(cli, cfg)
	if err != nil {
		return 1, err
	}
	st, err := store.Open()
	if err != nil {
		return 1, err
	}
	a := &App{ui: ui.Stderr(), store: st}

	baseSnapshot, err := a.ensureBaseSnapshot(cfg, cli.Rebuild, secrets)
	if err != nil {
		return 1, err
	}
	baseLayout, err := baseLayoutIdentity(st, baseSnapshot, cfg, secrets)
	if err != nil {
		return 1, err
	}
	name, err := SandboxName(cwd)
	if err != nil {
		return 1, err
	}
	sb, kind, err := a.openOrCreateSession(cli, cfg, resources, baseSnapshot, baseLayout, name, cwd, secrets)
	if err != nil {
		return 1, err
	}
	if err := a.applySessionConfig(sb, cfg, hostCopies); err != nil {
		return 1, err
	}
	a.ui.Crossing(outerHostname(), workspaceBase(cwd), kind, resources.cpus, resources.memory, resources.memoryMax)
	a.ui.Exposures(exposureReport(cfg, secrets, hostCopies, loaded.Sources))
	code, err := enterSession(a.ui, cfg, sb, secrets, cli.Command)
	if err != nil {
		return 1, err
	}
	if err := sb.RequestStop(); err != nil {
		a.ui.StopFailed(err)
	}
	return code, nil
}

func runAllow(cwd, host string, global bool) (int, error) {
	var path string
	if global {
		path = config.ConfigPath()
		// Directory only: a missing global file stays missing until the
		// allow edit writes a minimal one.
		if err := config.EnsureConfigDir(path); err != nil {
			return 1, err
		}
	} else {
		path = filepath.Join(cwd, config.LocalOverlayFile)
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			if _, err := config.InitWorkspace(cwd); err != nil {
				return 1, err
			}
		}
	}
	outcome, err := config.AllowHostInFile(path, host)
	if err != nil {
		return 1, err
	}
	if outcome == config.Added {
		fmt.Printf("allowed %s in %s\n", host, path)
		fmt.Println("takes effect on next entry (the session recreates automatically)")
	} else {
		fmt.Printf("%s is already allowed in %s\n", host, path)
	}
	return 0, nil
}

func connectExisting(cwd, explicit string) (*sandbox.Sandbox, error) {
	name, err := SandboxName(cwd)
	if err != nil {
		return nil, err
	}
	missing := fmt.Errorf("no box for %s (start one with box -c %s)", cwd, cwd)
	st, err := store.OpenExisting()
	if err != nil {
		return nil, missing
	}
	sb, err := sandbox.Get(st, name)
	if err != nil {
		return nil, missing
	}
	// Methods are short-lived processes that never request a stop; the VM
	// outlives them. A stopped VM boots with whatever secrets resolve now.
	var secrets []netstack.Secret
	if loaded, err := config.LoadFull(cwd, explicit); err == nil {
		if resolved, err := config.ResolveSecrets(loaded.Config); err == nil {
			secrets = liveSecrets(resolved)
		}
	}
	if err := resumeSession(sb, secrets); err != nil {
		return nil, err
	}
	return sb, nil
}

func fastMethod(rebuild, reset bool, command []string) (methods.Method, bool) {
	if rebuild || reset {
		return methods.Method{}, false
	}
	return methods.Parse(command)
}

// rejectBareUnknownCommand: a bare first word (no `--` separator) must name
// something box knows — a subcommand, a file method, or a configured
// agent. Anything else is a typo that would otherwise boot a whole VM just
// to fail inside the guest.
func rejectBareUnknownCommand(cli CLI, cfg config.Config) error {
	if cli.Sub != SubNone || len(cli.Command) == 0 || cli.Separator {
		return nil
	}
	if _, ok := fastMethod(cli.Rebuild, cli.Reset, cli.Command); ok {
		return nil
	}
	first := cli.Command[0]
	for _, agent := range cfg.Agents {
		if agent.Name == first {
			return nil
		}
	}
	return fmt.Errorf("unknown command %q: no box subcommand, method, or agent by that name. "+
		"Run it inside the guest with `box -- %s ...`.", first, first)
}
