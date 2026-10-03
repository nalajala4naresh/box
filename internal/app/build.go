package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/nalajala4naresh/box/internal/config"
	"github.com/nalajala4naresh/box/internal/netstack"
	"github.com/nalajala4naresh/box/internal/oci"
	"github.com/nalajala4naresh/box/internal/sandbox"
	"github.com/nalajala4naresh/box/internal/shell"
	"github.com/nalajala4naresh/box/internal/ui"
)

// BuildStage is one cached layer of the shared base.
type BuildStage struct {
	ID       string
	Snapshot string
	Script   string
}

// BuildStages derives the image → agents → custom layer chain. Snapshot
// names carry a cumulative digest, so changing one layer rebuilds it and
// its descendants while reusing its parents.
func BuildStages(cfg config.Config) ([]BuildStage, error) {
	type def struct{ id, script string }
	defs := []def{{"image", BuildScript("true")}}
	if len(cfg.Agents) > 0 {
		script, err := miseAgentsScript(cfg.Agents)
		if err != nil {
			return nil, err
		}
		defs = append(defs, def{"agents", script})
	}
	for _, layer := range cfg.Layers {
		defs = append(defs, def{layer.ID, BuildScript(layer.Script)})
	}

	lineage := sha256.New()
	lineage.Write([]byte(cfg.Sandbox.Image))
	stages := make([]BuildStage, 0, len(defs))
	for index, d := range defs {
		lineage.Write([]byte{0})
		lineage.Write([]byte(d.id))
		lineage.Write([]byte{0})
		lineage.Write([]byte(d.script))
		digest := fmt.Sprintf("%x", lineage.Sum(nil))
		stages = append(stages, BuildStage{
			ID:       d.id,
			Snapshot: fmt.Sprintf("%s-%02d-%s-%s", baseSnapshotPrefix, index+1, stageSlug(d.id), digest[:16]),
			Script:   d.script,
		})
	}
	return stages, nil
}

func miseAgentsScript(agents []config.AgentSpec) (string, error) {
	body := "mise use --global --pin --yes --jobs 4 --"
	seen := map[string]bool{}
	for _, agent := range agents {
		pkg, err := miseInstallPackage(agent.Package)
		if err != nil {
			return "", err
		}
		if !seen[pkg] {
			seen[pkg] = true
			body += " " + shell.Quote(pkg)
		}
	}
	return BuildScript(body), nil
}

func miseInstallPackage(pkg string) (string, error) {
	spec, err := config.MisePackage(pkg)
	if err != nil {
		return "", err
	}
	name, version, hasVersion := strings.Cut(spec, "@")
	if name == "github:tobi/try" {
		name = "gem:try-cli"
	}
	if hasVersion {
		return name + "@" + version, nil
	}
	return name, nil
}

// BuildScript boxs a layer body. Build layers run as the same unprivileged
// `user` the session runs as, with passwordless sudo for system packages.
// mise points at the shared /opt tree (user-owned in the image) so tools
// installed here are what the session sees.
//
// The guarded chown is a transition aid for base images that still ship
// /opt/mise root-owned; it is a no-op on current images.
//
// GitHub authentication for mise comes first, so even the earliest tool
// fetch in a stage sees an authenticated token.
func BuildScript(body string) string {
	return "set -eu\nexport HOME=" + GuestHome + "\nexport USER=" + GuestUser + "\n" +
		"export MISE_DATA_DIR=" + miseDataDir + "\nexport MISE_CONFIG_DIR=" + miseConfigDir + "\n" +
		"export MISE_TRUSTED_CONFIG_PATHS=" + miseConfigDir + "\n" +
		"export MISE_CACHE_DIR=" + GuestHome + "/.cache/mise\nexport MISE_STATE_DIR=" + GuestHome + "/.local/state/mise\n" +
		"export PATH=\"/usr/local/bin:" + miseDataDir + "/shims:/opt/box/bin:" +
		"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n" +
		"[ -O " + miseDataDir + " ] || sudo -n chown -R \"$(id -u):$(id -g)\" /opt/mise\n" +
		MiseGithubAuthSnippet() +
		body + "\n"
}

// MiseGithubAuthSnippet gives GitHub API clients a token as early as
// possible: prefer a real one from `gh` when the guest has it, otherwise
// alias the injected GH_TOKEN stand-in — box substitutes the real value
// on matching egress, so GITHUB_TOKEN (the name mise reads) authenticates
// without ever holding the secret. It never clobbers a set GITHUB_TOKEN,
// no-ops when neither source exists, and is safe under `set -eu`.
func MiseGithubAuthSnippet() string {
	standIn := config.SecretPlaceholder
	return "# Authenticate GitHub API clients (mise and friends) first: prefer a\n" +
		"# real token from gh when it has one, else alias the injected\n" +
		"# GH_TOKEN stand-in (substituted with the real value on matching\n" +
		"# egress).\n" +
		"if [ -z \"${GITHUB_TOKEN:-}\" ]; then\n" +
		"if command -v gh >/dev/null 2>&1; then\n" +
		"_box_gh_token=\"$(gh auth token 2>/dev/null)\" || _box_gh_token=\"\"\n" +
		"case \"$_box_gh_token\" in\n" +
		"\"\"|\"" + standIn + "\") ;;\n" +
		"*) GITHUB_TOKEN=\"$_box_gh_token\"; export GITHUB_TOKEN ;;\n" +
		"esac\n" +
		"unset _box_gh_token\n" +
		"fi\n" +
		"if [ -z \"${GITHUB_TOKEN:-}\" ] && [ -n \"${GH_TOKEN:-}\" ]; then\n" +
		"GITHUB_TOKEN=\"$GH_TOKEN\"\n" +
		"export GITHUB_TOKEN\n" +
		"fi\n" +
		"fi\n"
}

func stageSlug(id string) string {
	var b strings.Builder
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}

func (a *App) ensureBaseSnapshot(cfg config.Config, rebuild bool, secrets config.ResolvedSecrets) (string, error) {
	stages, err := BuildStages(cfg)
	if err != nil {
		return "", err
	}
	if len(stages) == 0 {
		return "", errors.New("base layout has no stages")
	}
	base := stages[len(stages)-1].Snapshot
	if _, err := sandbox.OpenSnapshot(a.store, base); !rebuild && err == nil {
		return base, nil
	}
	a.ui.SettingUpBase()
	if rebuild {
		// Snapshots are promoted only once complete, so an interrupted
		// rebuild keeps the current chain usable.
		a.ui.Rebuild(len(stages))
	}
	parent := ""
	for _, stage := range stages {
		if _, err := sandbox.OpenSnapshot(a.store, stage.Snapshot); !rebuild && err == nil {
			a.ui.LayerReused(stage.ID)
			parent = stage.Snapshot
			continue
		}
		if err := a.buildLayer(cfg, stage, parent, secrets); err != nil {
			return "", err
		}
		parent = stage.Snapshot
	}
	return base, nil
}

func (a *App) buildLayer(cfg config.Config, stage BuildStage, parent string, secrets config.ResolvedSecrets) error {
	name := "box-build-" + stageSlug(stage.ID)
	live := a.ui.StartLayer(stage.ID)
	defer live.Close()

	spec := sandbox.Spec{
		Name:     name,
		CPUs:     cfg.Sandbox.CPUs,
		Memory:   cfg.Sandbox.Memory,
		MaxMem:   cfg.Sandbox.MemoryMax,
		Shell:    "/bin/bash",
		User:     GuestUser,
		Hostname: "box-build",
		Env:      []sandbox.EnvVar{{Key: "HOME", Value: GuestHome}, {Key: "USER", Value: GuestUser}},
		Policy:   netstack.Policy{Public: true},
		Secrets:  secretDecls(secrets),
		Timezone: hostTimezone(),
	}
	source := sandbox.Source{Snapshot: parent}
	if parent == "" {
		// The image stage only runs on first build or --rebuild; both want
		// the registry's current tag, so the manifest is always re-checked
		// and only changed layers are fetched.
		live.Phase("pulling image")
		image, err := waitWithLive(live, func(ctx context.Context) (oci.Image, error) {
			return oci.Ensure(ctx, a.store, cfg.Sandbox.Image, func(line string) {
				live.FeedStderr([]byte(line + "\n"))
			})
		})
		if err != nil {
			live.Fail("pull failed")
			return err
		}
		source = sandbox.Source{ImageRootfs: image.Rootfs, ImageDigest: image.Digest, ImageEnv: image.Env}
	}

	live.Phase("creating build vm")
	sb, err := waitWithLive(live, func(context.Context) (*sandbox.Sandbox, error) {
		sb, err := sandbox.Create(a.store, spec, source, liveSecrets(secrets))
		if err != nil {
			return nil, fmt.Errorf("create layer sandbox %s: %w", stage.ID, err)
		}
		return sb, nil
	})
	if err != nil {
		live.Fail("create failed")
		return err
	}
	// Never leave a build VM running behind a failure or interrupt.
	defer func() {
		if sb.Status() != sandbox.Stopped {
			sb.RequestStop()
		}
	}()

	live.Phase("disabling IPv6 egress")
	if err := ensureIPv4Egress(sb); err != nil {
		live.Fail("network setup failed")
		return err
	}

	if parent == "" {
		live.Phase("checking image contract")
		if err := checkImageContract(sb, cfg.Sandbox.Image); err != nil {
			live.Fail("unsupported image")
			return err
		}
	}

	live.Phase("running setup")
	setupErr := runSetup(live, stage.ID, sb, stage.Script)
	if setupErr == nil {
		live.Phase("syncing and stopping build vm")
	}
	_, stopErr := waitWithLive(live, func(context.Context) (struct{}, error) {
		if err := sb.Stop(); err != nil {
			return struct{}{}, fmt.Errorf("stop layer sandbox %s: %w", stage.ID, err)
		}
		return struct{}{}, nil
	})
	if setupErr != nil {
		return setupErr
	}
	if stopErr != nil {
		live.Fail("stop failed")
		return stopErr
	}

	live.Phase("saving shared snapshot")
	if _, err := waitWithLive(live, func(context.Context) (sandbox.Snapshot, error) {
		snap, err := sandbox.SnapshotFromSandbox(a.store, stage.Snapshot, name)
		if err != nil {
			return snap, fmt.Errorf("snapshot layer %s: %w", stage.ID, err)
		}
		return snap, nil
	}); err != nil {
		live.Fail("snapshot failed")
		return err
	}
	_, leftover := waitWithLive(live, func(context.Context) (struct{}, error) {
		return struct{}{}, sandbox.Remove(a.store, name)
	})
	live.Succeed()
	if leftover != nil {
		a.ui.Leftover(name, leftover)
	}
	return nil
}

// errInterrupted is returned when ctrl-c lands during a live phase.
var errInterrupted = errors.New("interrupted")

// waitWithLive runs fn while keeping the live region ticking, and turns
// ctrl-c into an interrupt.
func waitWithLive[T any](live *ui.Live, fn func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := fn(ctx)
		done <- result{value, err}
	}()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	ticks := time.NewTicker(ui.SpinPeriod())
	defer ticks.Stop()
	for {
		select {
		case <-interrupt:
			cancel()
			live.Interrupt()
			var zero T
			return zero, errInterrupted
		case <-ticks.C:
			live.Tick()
		case r := <-done:
			return r.value, r.err
		}
	}
}

func runSetup(live *ui.Live, layerID string, sb *sandbox.Sandbox, script string) error {
	events, cancelStream, err := sb.ShellStream(script, sandbox.ExecOptions{Timeout: 45 * time.Minute})
	if err != nil {
		live.Fail("setup failed")
		return fmt.Errorf("start layer %s: %w", layerID, err)
	}
	defer cancelStream()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	ticks := time.NewTicker(ui.SpinPeriod())
	defer ticks.Stop()
	for {
		select {
		case <-interrupt:
			live.Interrupt()
			return errInterrupted
		case <-ticks.C:
			live.Tick()
		case event, ok := <-events:
			if !ok {
				live.Fail("no exit code")
				return fmt.Errorf("layer %s ended without an exit code", layerID)
			}
			live.FeedStdout(event.Stdout)
			live.FeedStderr(event.Stderr)
			switch {
			case event.Err != nil:
				live.Fail("failed to start")
				return fmt.Errorf("layer %s failed to start: %w", layerID, event.Err)
			case event.Exited && event.Code == 0:
				return nil
			case event.Exited:
				live.Fail(fmt.Sprintf("exit %d", event.Code))
				return fmt.Errorf("layer %s failed", layerID)
			}
		}
	}
}

// checkImageContract verifies the base image provides what every layer
// and session assumes (see Containerfile): an unprivileged `user` with
// passwordless sudo, and zsh for sessions.
func checkImageContract(sb *sandbox.Sandbox, image string) error {
	out, err := rootShell(sb, `missing=""
id `+GuestUser+` >/dev/null 2>&1 || missing="$missing user-account"
command -v sudo >/dev/null 2>&1 || missing="$missing sudo"
[ -x /bin/zsh ] || missing="$missing /bin/zsh"
printf '%s' "$missing"`)
	if err != nil {
		return fmt.Errorf("inspect image %s: %w", image, err)
	}
	missing := strings.Fields(string(out.Stdout))
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("image %s is not a box base image (missing: %s). "+
		"Layers run as `%s` with passwordless sudo and sessions use zsh and mise; "+
		"build one from Containerfile for linux/%s and set sandbox.image to it",
		image, strings.Join(missing, ", "), GuestUser, runtime.GOARCH)
}
