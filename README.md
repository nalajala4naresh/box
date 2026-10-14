# box

Run commands and coding agents in a disposable Ubuntu 24.04 microVM built around the folder you are in.

```text
host project  ── ~/workspace ──>  microVM
                              ├─ pi / omp / codex / claude
                              ├─ shell tools
                              └─ default-deny network
```

`box` is useful when you want an agent to inspect a project without giving it your host machine, when you are reviewing a pull request, or when you want a clean VM for a short-lived project trial.

## Install

With [mise](https://mise.jdx.dev/):

```bash
mise u -g --pin github:nalajala4naresh/box
```

This uses the GitHub release backend. Push a `v*` tag to build the Linux release asset. macOS compilation is tracked separately while the upstream microsandbox dependency is repaired. Until a release exists, install from a Rust checkout:

```bash
mise use --global --pin github:nalajala4naresh/box
```

From a Rust checkout:

```bash
cargo install --git https://github.com/nalajala4naresh/box box
```

## Start a VM

Run `box` from the project directory:

```bash
cd ~/src/my-project
box
```

The current directory is mounted in the VM at `/home/user/workspace`, so shells start in the project. The VM starts from the shared published base container and is cached by workspace, so later starts are quick. The base snapshot is shared; your project VM is separate.

Run one command without opening a shell:

```bash
box -- git status
box -- ruby -v
box -- make test
```

Open a shell explicitly:

```bash
box -- bash
```

A normal interactive `box` starts a login zsh session. The base prompt identifies the guest clearly:

```text
[vm:project-name] ~/workspace ❯
```

## Run an agent inside the VM

`pi`, `omp`, `codex`, and `claude` are installed as guest commands. Choose one of them after `--`:

```bash
box -- pi
box -- omp
box -- codex
box -- claude
```

Host agent configuration (`~/.pi`, `~/.omp`, ...) is not copied in by default. Opt in with `host-copy` on an agent if you want that directory in the project VM; it stays on the host and is never baked into the shared base image.

This is the simplest mode when the agent should work directly in the isolated project environment.

## Use an outside agent

An agent running on the host can operate the VM without attaching a terminal. Start the project VM once:

```bash
box -- /bin/true
```

Then use the file and command methods:

```bash
box -c "$PWD" ls
box -c "$PWD" read README.md
box -c "$PWD" grep TODO src
box -c "$PWD" find src -name '*.rs'
box -c "$PWD" write notes.md 'review notes'
box -c "$PWD" bash 'cargo test'
```

Relative paths refer to the project mounted at `/home/user/workspace`. These methods execute inside the VM and return their output; they do not attach a shell or stop the VM. This is the agent-on-the-outside mode: the orchestrator stays on the host while file inspection, edits, searches, and commands run in the guest.

The available methods are:

- `ls [args...]` — list project files
- `read PATH[:SELECTOR]` — read a file or selected lines
- `write PATH CONTENT` — write a file; stdin is used when content is omitted
- `find [args...]` — find project files
- `grep PATTERN [PATH]` — recursive grep
- `bash COMMAND` — run `/bin/sh -c` inside the VM

Examples of line selectors:

```bash
box -c "$PWD" read src/main.rs:40
box -c "$PWD" read src/main.rs:40-80
box -c "$PWD" read src/main.rs:40:10
```

## Guest user

Everything runs as the unprivileged `user` account inside the VM (`HOME=/home/user`), with passwordless `sudo` for the cases that need it; the container images have no root mode either. Only box's own setup plumbing runs as root. The project mount presents your files as owned by `user`, so `~/workspace` is writable without renumbering or chowning anything, and files created in the VM come back owned by you. Ownership and permission changes made inside the VM are recorded in a `user.msb.override_stat` extended attribute on the files the VM creates or changes, and never applied to the real files: a `chmod +x` inside the VM is visible only inside the VM, and files the VM creates are private (`600`/`700`) on the host.

If you opt in with `host-copy`, imported host agent configuration lands under `/home/user`.

## Desktop image

`ghcr.io/nalajala4naresh/wrap:desktop` (`Containerfile.desktop`) layers a headless desktop on the base image:

- X display `:1` (Xvfb, 1280x800) running a minimal XFCE — navy backdrop, one bottom dock with Chrome, Thunar and Terminal — autostarted from login shells; `box-desktop start|stop|status|url`.
- One persistent Google Chrome on that desktop (no window until agent-browser or the dock opens one) with CDP on `127.0.0.1:9222`. The setup speedrun is baked in system-wide: managed policies (`/etc/opt/chrome/policies/managed`) and `initial_preferences` disable sign-in, sync, default-browser, privacy-sandbox, promo, password/autofill and keyring prompts, so neither agents nor humans ever see first-run UI.
- `agent-browser` preinstalled and preconfigured (`~/.agent-browser/config.json`, `cdp: 9222`) to attach to that Chrome: `agent-browser open https://example.com` acts in the same browser you see over VNC, so you can watch, log in, or take over and hand back. A project `./agent-browser.json` still overrides (drop `cdp` for an isolated headed Chrome).
- View it over noVNC at `http://127.0.0.1:6080/vnc.html` (or VNC on 5900, no password) by publishing the ports in `~/.config/box/config.yml`; the host side is loopback-only.

Use it from box:

```yaml
# ~/.config/box/config.yml
sandbox:
  image: ghcr.io/nalajala4naresh/wrap:desktop
network:
  ports: [6080]        # host 127.0.0.1:6080 -> guest noVNC; "HOST:GUEST" also works
```

```bash
box -- agent-browser open https://example.com     # then open http://127.0.0.1:6080/vnc.html
```

Or standalone:

```bash
docker run -d -p 127.0.0.1:6080:6080 ghcr.io/nalajala4naresh/wrap:desktop   # desktop + chrome
docker run -it ghcr.io/nalajala4naresh/wrap:desktop                         # shell as `user`; desktop autostarts
```

## Network and credentials

The VM starts with a default-deny network policy. Project traffic is limited to the configured allowlist, which includes GitHub by default. Custom layers and agents are applied after the published base container is loaded.

You can add or remove allowed hosts in the box configuration. A project does not inherit the host's unrestricted network access.

Host secrets are not mounted into `~/workspace`, copied into the image, or exposed through an always-on host proxy such as an iron-proxy. When explicitly configured, a credential is granted only to the named hosts and appears to guest processes as a scoped pseudo-token. The VM cannot use that credential for arbitrary destinations.

For example, the default GitHub credential is available only for GitHub hosts. Every build stage and session shell first tries `gh auth token` for a real token and otherwise aliases the live `GH_TOKEN` stand-in to `GITHUB_TOKEN`, so tool installers such as mise authenticate their GitHub API calls instead of hitting anonymous rate limits (header injection substitutes the real value on matching egress). On entry, box prints the merge stack (embedded defaults, `config.yml`, `config.d/*.yml`, `BOXFILE`, `--config`) and a compact exposure report: `network-access: deny` (green) or `allow` (red), reachable hosts with shared credentials grouped on one line and declared headers indented beneath, `deny: everything else`, plus ports, copies, and env when present — without ever printing secret values.

## Configuration

The built-in defaults live in the release. On first run box writes `~/.config/box/config.yml` with the entire default set commented out — pure documentation that changes nothing:

```text
~/.config/box/config.yml        # all defaults commented; uncomment to override
~/.config/box/config.d/*.yml   # personal drop-ins, lexical order
```

Precedence is embedded defaults, then the user config, then `~/.config/box/config.d/*.yml` drop-ins in lexical order, then `BOXFILE` in the workspace, then `--config PATH` / `$BOX_CONFIG`. `box config` prints that fully merged result as YAML without booting a VM.

Keep personal overrides in `config.d/` (`10-shopify.yml`, `20-network.yml`, …) and `config.yml` close to its commented template. For example:

```yaml
network:
  allow:
    - .gitlab.com

agents:
  - name: omp
    package: github:can1357/oh-my-pi@latest
    host-copy: ~/.omp
```

A workspace-local layer comes from `box init`, which writes a starter `BOXFILE` in the current workspace and exits without booting a VM:

```bash
cd ~/src/my-project
box init
```

Secrets name a guest `env` var, a `source`, explicit `headers`, and a `hosts` map. The guest var always holds the constant stand-in `NOT-AN-ACTUAL-KEY`, never the real value:

```yaml
secrets:
  - env: EXTRA_TOKEN
    source: $EXTRA_TOKEN
    headers:
      X-Api-Token: $EXTRA_TOKEN
    hosts:
      api.example.com: {allow: true}
```

A source is `$(command)`, `$HOST_VAR`, `file:/path`, or a literal. Only live (resolved) secret hosts fold into the network allowlist automatically — a skipped optional secret whitelists nothing; `network.deny` still wins. Missing variables, failed commands, and empty command results stop setup before VM work begins, unless the secret is marked `optional: true` — the shipped OpenRouter/OpenAI/Anthropic passthroughs are optional and skip quietly when their host variable is absent.

## Good uses

- Review a pull request with an agent that cannot modify the host system.
- Give an agent a clean, reproducible project environment.
- Try a repository or toolchain without installing it on the host.
- Run build and test commands with a disposable guest filesystem.
- Let a host-side agent inspect and edit files through a narrow command surface.
- Keep multiple experimental project VMs isolated from one another.

## Useful options

```bash
box --reset       # recreate this project's VM from the current base
box --rebuild     # rebuild the shared base layers
box --cpus 8      # override project VM CPUs
box --memory 8192 # set the project VM memory ceiling in MiB
box -c DIR ...    # target an existing VM for a method call
box init          # write BOXFILE here; exits without booting a VM
box allow HOST    # append HOST to network.allow in BOXFILE (-g for global)
box log           # denied egress requests from this session's logs (--tail N, --follow)
box config        # print the fully merged config as YAML (no VM)
box --network-allow-everything -- CMD  # open egress for this entry only
box --config FILE # one-off explicit config overlay (or $BOX_CONFIG)
```

`--rebuild` and `--reset` are lifecycle operations. Do not use them with the outside-agent methods.

## Status

`box` is designed around [microsandbox](https://github.com/superradcompany/microsandbox) and starts from the `ghcr.io/nalajala4naresh/wrap:v1.0.0` Ubuntu 24.04 container with common development tools, mise, zsh, and configured agents layered on top.
