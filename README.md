# box (Go + libkrun)

A Go implementation of [tobi/wrap](https://github.com/tobi/wrap): run commands and coding agents in a disposable Arch Linux microVM built around the folder you are in. The original is Rust on top of microsandbox; this port drives [libkrun](https://github.com/containers/libkrun) directly through [libkrun-go](https://github.com/nalajala4naresh/libkrun-go) and implements the pieces microsandbox used to provide (OCI pulls, layer snapshots, a guest agent, the egress policy, and secret substitution) itself.

The CLI, config schema, merge rules, layer caching, and session semantics match the Rust version, so its README applies: `box`, `box -- CMD`, `box -c DIR ls|read|grep|find|write|bash`, `box init|allow|config|log`, `--reset`, `--rebuild`, `--cpus`, `--memory`, `--memory-boot`, `--config`, `--network-allow-everything`/`--yolo`, `--skill`.

## Requirements

- macOS on Apple silicon (Hypervisor.framework) or Linux with KVM.
- libkrun built with networking (`NET=1`) and libkrunfw. On macOS:

  ```bash
  brew tap slp/krun
  brew install slp/krun/libkrun pkg-config   # bottled with BLK=1 NET=1
  ```

  Recent Homebrew refuses formulae from taps you have not trusted; run `brew trust slp/krun` first if you accept that tap.
- Go 1.26+.

## Build

```bash
make            # cross-compiles the guest agent, builds bin/box with -tags krun_net, codesigns on macOS
make install    # into ~/.local/bin (PREFIX/BINDIR override)
make test
```

On macOS the binary must carry the `com.apple.security.hypervisor` entitlement (`entitlements.plist`); `make` signs it ad hoc. A plain `go build` produces a binary whose VMs fail to start.

## How it works

```text
box (host CLI)                         box __vm <sandbox>  (detached, one per running VM)
  config merge, layer chain,              ├─ userspace network (gVisor netstack)
  sessions, UI                            │    DNS · egress policy · TLS secret substitution · published ports
  │                                       ├─ control socket (live secret rotation)
  │  vsock-mapped unix socket             └─ libkrun-go → krun_start_enter()
  └──────────────────────────────────────────► microVM
                                                 libkrun init → /.box/box-agent
                                                   mounts, eth0, hostname, CA trust
                                                   exec (pipes or pty) · file ops
```

- **Images and snapshots.** The configured image (default `ghcr.io/tobi/wrap:latest`) is pulled with go-containerregistry (manifest re-checked on every image-stage build, layers cached) and flattened into a rootfs directory, honoring OCI whiteouts and resolving every path inside the root. Guest ownership and modes are stored the way libkrun's macOS virtio-fs expects them (`user.containers.override_stat` xattrs), so `sudo` and friends see root-owned setuid binaries while the host files stay yours. Each layer (`image`, `agents`, your `layers`) runs in a build VM and is frozen as a snapshot; snapshot names carry the same cumulative digests as the Rust version. Sessions are APFS clones (`clonefile`) of the final snapshot, so a new workspace costs metadata, not a copy.
- **Case-sensitive storage.** Linux images contain names that differ only by case. When `$BOX_HOME` (default `~/.box`) is on a case-insensitive APFS volume, box keeps its data in a Case-sensitive APFS sparse bundle (`~/.box/data.sparsebundle`) and attaches it on demand. No root is needed.
- **VM process.** libkrun's `krun_start_enter` takes over the calling process and never returns, so each VM runs in its own `box __vm` process, detached from the terminal. That is what lets `box -c DIR read ...` reach a VM started by another invocation. Secret values reach that process over a pipe and stay in memory; nothing secret is written to disk.
- **Guest agent.** `cmd/box-agent` is a static Linux binary embedded in `box` and installed at `/.box/box-agent`. libkrun's init runs it as the workload. It mounts the workspace (virtio-fs), configures `eth0`, sets the hostname and timezone, trusts box's CA, disables IPv6, then serves exec, pty attach, and file operations on a vsock port that libkrun maps to `~/.box/run/<sandbox>/agent.sock`.
- **Network.** The VM gets a virtio-net device whose backend is a datagram socket pair. The host end is a gVisor TCP/IP stack, so every guest connection is a host-side decision:
  - DNS only goes to the gateway (`192.168.127.1`), which resolves on the host and refuses names covered by `network.deny`.
  - TCP is allowed on 80/443 to addresses the guest resolved from an allowed name (exact, `.suffix`, or `*.wildcard`). On 443 the TLS SNI must be allowed too. `deny` always wins, and `allow_everything` opens everything except denied names.
  - Build VMs use the public profile: any public address, no private ranges.
  - HTTPS to hosts of live secrets is intercepted with a per-install CA (`~/.box/ca/`, key mode 0600). The guest's `NOT-AN-ACTUAL-KEY` stand-in is replaced with the real value in request headers (including Basic credentials) on the way out, and only for those hosts. Rotated values apply to the next connection without a restart.
  - `network.ports` are published on host `127.0.0.1`.
  - Denials and lookups go to `~/.box/data/sandboxes/<sandbox>/logs/system.log`, which `box log` reads.

## Differences from the Rust version

- **Memory.** libkrun has no balloon, so the VM's RAM is the configured ceiling (`memory_max`, at least 4 GiB, as before). The hypervisor only backs pages the guest touches. `memory` is still recorded and shown.
- **Host-copy archives.** These are built in Go instead of GNU `tar`, so they work with macOS's bsdtar too.
- **uid realignment.** It skips the workspace share (`find -xdev`), so host files never get ownership xattrs.
- **Non-interactive sessions.** `box -- CMD` streams output as it arrives, and forwards stdin when stdin is not a terminal.
- **Linux hosts.** libkrun's Linux virtio-fs uses real ownership, so building images as a non-root user leaves files owned by you inside the guest. Run as root (or use macOS) for faithful ownership.
- **Unchanged digests.** Session recreation still keys on the snapshot digest, published ports, network lists, secret structure, and host-copies.

## Layout

```text
cmd/box              host CLI entry (also the `__vm` process)
cmd/box-agent        guest agent (linux)
internal/app          CLI parsing, layer builds, sessions, crossing, `box log`
internal/config       strict schema, overlay merging, secrets, `box allow` edits
internal/ui           live layer rail, crossing line, exposure report
internal/methods      fast methods: ls/read/grep/find/write/bash
internal/sandbox      VM runtime: sandboxes, snapshots, exec/attach/fs client
internal/vm           libkrun-go configuration and krun_start_enter
internal/netstack     userspace network, policy, DNS, TLS interception
internal/oci          image pull and layer extraction
internal/store        on-disk layout, case-sensitive volume, clones
internal/agent        host/guest protocol; server/ is the agent's handler
resources             default.yml, skill.md (embedded)
```

## Image architecture

libkrun runs guests of the host architecture only. As of this writing `ghcr.io/tobi/wrap:latest` and `:desktop`, and their `archlinux:latest` base, are published for linux/amd64 only. They work on x86_64 Linux hosts, but Apple silicon needs a linux/arm64 image built from `Containerfile` (for example on an Arch Linux ARM base) and set as `sandbox.image`. Pulling an image without a matching architecture fails with a message that says so.
