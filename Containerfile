FROM docker.io/ubuntu:24.04

# Build-time only (an ARG, not ENV): keeps apt from prompting without
# leaking noninteractive mode into interactive sessions.
ARG DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# Toolchain lives at absolute paths under /opt, NOT under $HOME.
#
# Rationale: mise resolves its config/data/cache/shims relative to `~` by
# default, which hard-wires the whole toolchain to /root. That breaks two real
# use cases:
#   1. Running the container as a non-root uid (e.g. podman --userns=keep-id):
#      /root is 0750, so uid!=0 cannot even traverse it to reach the shims.
#   2. Overriding HOME (e.g. HOME=/workspace/.sandbox-home): mise then looks for
#      its config/installs under the new HOME, finds nothing, and every shim
#      fails with "<tool> is not a valid shim".
#
# Pinning MISE_* to absolute paths decouples the toolchain from $HOME entirely,
# so HOME is free to be whatever the caller wants.
#
# DATA/CONFIG are shared state under /opt, owned by `user` (installs work
# without sudo) and world-readable (root can still run the shims).
# CACHE/STATE deliberately stay at mise's per-user defaults ($HOME/.cache/mise,
# $HOME/.local/state/mise). A shared cache dir (e.g. under /tmp) ends up owned
# by whichever uid touched it first and then breaks mise for every other uid.
#
# MISE_TRUSTED_CONFIG_PATHS is required, not cosmetic: mise only auto-trusts a
# global config it resolves through $HOME. With the config at an absolute path
# outside HOME, an overridden HOME makes mise silently list it under
# `ignored_config_files` and every shim fails with "No version is set for
# shim: <tool>". Declaring the path trusted keeps the toolchain working for any
# HOME value.
#
# RUSTUP_HOME/CARGO_HOME follow the same rule. mise's rust backend drives
# rustup, which otherwise defaults to ~/.rustup and ~/.cargo: the toolchain
# would land in /root at build time, and `user` would re-download it on first
# `rustc`. Under /opt/mise it is installed once and shared.
# ---------------------------------------------------------------------------
ENV MISE_DATA_DIR=/opt/mise/data \
    MISE_CONFIG_DIR=/opt/mise/config \
    MISE_TRUSTED_CONFIG_PATHS=/opt/mise/config \
    RUSTUP_HOME=/opt/mise/rustup \
    CARGO_HOME=/opt/mise/cargo

# Build-time identity only; the runtime identity is set at the end of the file.
ENV HOME=/root \
    USER=root \
    PATH=/usr/local/bin:/opt/mise/data/shims:/opt/box/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    STARSHIP_CONFIG=/etc/box/starship.toml \
    LANG=C.UTF-8

# Unprivileged identity. uid/gid 1000 matches the common single-user host uid,
# so bind-mounted files map 1:1 under `--userns=keep-id` without chowning.
ENV BOX_UID=1000 \
    BOX_GID=1000 \
    BOX_USER_NAME=user \
    BOX_USER_HOME=/home/user

# Ubuntu's own archive (archive/security, or ports on arm64): it is what
# box's default network allowlist permits (.ubuntu.com), so
# `sudo apt-get install` keeps working inside the VM. gh and mise come from
# their upstream apt repos (.github.com / .jdx.dev, also allowlisted) so they
# stay current like the Arch packages did; starship is not packaged for 24.04.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && curl -fsSL https://mise.jdx.dev/gpg-key.pub \
      | gpg --dearmor -o /etc/apt/keyrings/mise-archive-keyring.gpg \
 && chmod a+r /etc/apt/keyrings/*.gpg \
 && arch="$(dpkg --print-architecture)" \
 && echo "deb [arch=$arch signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
 && echo "deb [arch=$arch signed-by=/etc/apt/keyrings/mise-archive-keyring.gpg] https://mise.jdx.dev/deb stable main" \
      > /etc/apt/sources.list.d/mise.list \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
      build-essential \
      clang \
      cmake \
      eza \
      fd-find \
      file \
      gdb \
      gh \
      git \
      jq \
      less \
      libyaml-dev \
      mise \
      nano \
      ninja-build \
      openssh-client \
      procps \
      python-is-python3 \
      python3 \
      python3-pip \
      python3-venv \
      ripgrep \
      ruby \
      sudo \
      tar \
      unzip \
      util-linux \
      xz-utils \
      zsh \
 && ln -sf /usr/bin/fdfind /usr/local/bin/fd \
 && curl -fsSL https://starship.rs/install.sh | sh -s -- --yes --bin-dir /usr/local/bin \
 && install -d /opt/mise /opt/box/bin /etc/box \
 && /usr/bin/mise use --global --pin --yes --jobs 4 -- \
      rust@latest \
      go@latest \
      bun@latest \
      node@latest \
      pnpm@latest \
      python@latest \
      uv@latest \
 && if ! grep -qx '/bin/zsh' /etc/shells; then echo /bin/zsh >> /etc/shells; fi \
 && if ! grep -qx '/usr/bin/zsh' /etc/shells; then echo /usr/bin/zsh >> /etc/shells; fi \
 && (chsh -s /bin/zsh root || true) \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /root/.cache /root/.local/state/mise \
 && chmod -R a+rX /opt/mise /opt/box \
 && (find /opt/mise/data/shims -type f -exec chmod a+rx {} + 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Unprivileged `user` (uid/gid 1000) with passwordless sudo.
# The project bind-mounts at ${BOX_USER_HOME}/workspace, owned by that uid
# so it is writable in user mode without any host-side chown.
# /opt/mise is owned by that uid too: the toolchain lives at a HOME-independent
# path, but `user` must be able to `mise use`/`mise install` into it without
# sudo. root still reads it fine (a+rX).
# Ubuntu's sudoers pins a secure_path without the mise shims; 12-box-path
# restores them and keeps MISE_*/RUSTUP_HOME/CARGO_HOME through env_reset, so `sudo <tool>` resolves
# the same shared toolchain.
# ubuntu:24.04 ships its own `ubuntu` account at uid/gid 1000; drop it first or
# the uid is taken and `user` is silently never created.
# ---------------------------------------------------------------------------
RUN (userdel -r ubuntu 2>/dev/null || true) \
 && (groupdel ubuntu 2>/dev/null || true) \
 && (groupadd -g "${BOX_GID}" "${BOX_USER_NAME}" 2>/dev/null || true) \
 && (useradd -m -d "${BOX_USER_HOME}" -u "${BOX_UID}" -g "${BOX_GID}" \
      -s /bin/zsh "${BOX_USER_NAME}" 2>/dev/null || true) \
 && usermod -aG sudo "${BOX_USER_NAME}" \
 && printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "${BOX_USER_NAME}" \
      > /etc/sudoers.d/10-box-user \
 && printf '%%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/11-box-sudo \
 && printf 'Defaults secure_path="%s"\nDefaults env_keep += "MISE_DATA_DIR MISE_CONFIG_DIR MISE_TRUSTED_CONFIG_PATHS RUSTUP_HOME CARGO_HOME"\n' \
      /usr/local/bin:/opt/mise/data/shims:/opt/box/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
      > /etc/sudoers.d/12-box-path \
 && chmod 0440 /etc/sudoers.d/10-box-user /etc/sudoers.d/11-box-sudo /etc/sudoers.d/12-box-path \
 && visudo -c \
 && install -d -o "${BOX_UID}" -g "${BOX_GID}" "${BOX_USER_HOME}/workspace" \
 && chown -R "${BOX_UID}:${BOX_GID}" "${BOX_USER_HOME}" /opt/mise \
 && chmod 0755 "${BOX_USER_HOME}"

# ---------------------------------------------------------------------------
# Shell environment. MISE_* and PATH are re-exported here so they survive
# `su`, `sudo -i`, and login shells that reset the environment. One file,
# sourced by /etc/profile (sh/bash login) and /etc/zsh/zshenv (every zsh).
# The PATH prepend is idempotent so nested shells do not stack duplicates.
# ---------------------------------------------------------------------------
RUN cat > /etc/profile.d/box.sh <<'EOF'
export MISE_DATA_DIR=/opt/mise/data
export MISE_CONFIG_DIR=/opt/mise/config
export MISE_TRUSTED_CONFIG_PATHS="${MISE_TRUSTED_CONFIG_PATHS:-/opt/mise/config}"
export RUSTUP_HOME=/opt/mise/rustup
export CARGO_HOME=/opt/mise/cargo
export STARSHIP_CONFIG=/etc/box/starship.toml
case ":$PATH:" in
  *":/opt/mise/data/shims:"*) ;;
  *) export PATH="/usr/local/bin:/opt/mise/data/shims:/opt/box/bin:$PATH" ;;
esac
EOF

RUN cat > /etc/zsh/zshenv <<'EOF'
[ -f /etc/profile.d/box.sh ] && . /etc/profile.d/box.sh
if [[ -o interactive && -t 1 ]]; then
  eval "$(/usr/bin/mise activate zsh)"
  eval "$(starship init zsh)"
fi
EOF

# Skeleton dotfiles, installed for BOTH root and user so either mode gets the
# same shell. Kept minimal and identity-free: git author/committer values come
# from the environment, never baked into the image.
RUN cat > /etc/box/skel.zshrc <<'EOF'
# box interactive shell
setopt HIST_IGNORE_DUPS SHARE_HISTORY INC_APPEND_HISTORY
HISTSIZE=10000
SAVEHIST=10000
HISTFILE="${XDG_STATE_HOME:-$HOME/.local/state}/zsh_history"
mkdir -p "$(dirname "$HISTFILE")" 2>/dev/null || true

autoload -Uz compinit && compinit -u 2>/dev/null || true

alias ls='eza --group-directories-first'
alias ll='eza -l --git --group-directories-first'
alias la='eza -la --git --group-directories-first'
alias cat='cat'
alias g=git
EOF

RUN cat > /etc/box/skel.profile <<'EOF'
# box login shell (sh/bash compatible)
[ -f /etc/profile.d/box.sh ] && . /etc/profile.d/box.sh
EOF

# `safe.directory = *` is deliberate: the project is a bind mount whose host
# owner uid frequently differs from the in-container uid, and git otherwise
# aborts every command with "detected dubious ownership in repository".
RUN cat > /etc/box/skel.gitconfig <<'EOF'
[safe]
	directory = *
[init]
	defaultBranch = main
[advice]
	detachedHead = false
EOF

RUN set -eu; \
    for target in /root "${BOX_USER_HOME}"; do \
      install -d "$target"; \
      cp /etc/box/skel.zshrc     "$target/.zshrc"; \
      cp /etc/box/skel.profile   "$target/.profile"; \
      cp /etc/box/skel.profile   "$target/.zprofile"; \
      cp /etc/box/skel.profile   "$target/.bashrc"; \
      cp /etc/box/skel.gitconfig "$target/.gitconfig"; \
      install -d "$target/.local/state" "$target/.config" "$target/.cache"; \
    done; \
    chown -R "${BOX_UID}:${BOX_GID}" "${BOX_USER_HOME}"; \
    cp /etc/box/skel.zshrc /etc/skel/.zshrc; \
    cp /etc/box/skel.profile /etc/skel/.profile; \
    cp /etc/box/skel.gitconfig /etc/skel/.gitconfig

RUN cat > /etc/box/starship.toml <<'EOF'
add_newline = true
command_timeout = 200
format = "$hostname$directory$git_branch$git_status$character"
right_format = "$cmd_duration"

[hostname]
ssh_only = false
trim_at = ""
format = "[\\[container:$hostname\\]](bold #c4a7e7) "

[character]
success_symbol = "[❯](bold #89ddff)"
error_symbol = "[✗](bold #f78c6c)"

[directory]
truncation_length = 2
truncation_symbol = "…/"
repo_root_style = "bold #89ddff"
repo_root_format = "[$repo_root]($repo_root_style)[$path]($style)[$read_only]($read_only_style) "

[git_branch]
format = "[$branch]($style) "
style = "italic #c4a7e7"

[git_status]
format = "[$all_status]($style)"
style = "#89ddff"
ahead = "⇡${count} "
diverged = "⇕⇡${ahead_count}⇣${behind_count} "
behind = "⇣${count} "
conflicted = "! "
up_to_date = ""
untracked = "? "
modified = "~ "
stashed = ""
staged = ""
renamed = ""
deleted = ""

[cmd_duration]
min_time = 2000
format = "[· $duration](#78909c)"
EOF

# ---------------------------------------------------------------------------
# Entrypoint: the workload always runs as the unprivileged `user`.
#
#   default / started as root   -> setpriv to uid/gid 1000, HOME=/home/user
#   --user <uid>                -> runs as that uid; HOME is corrected because
#                                  a bare --user would otherwise inherit an
#                                  unusable HOME.
#
# There is no root mode. Need root inside? `sudo -i` (passwordless) or
# `docker exec -u root`.
#
# BIND MOUNTS + ROOTLESS PODMAN: container uid 1000 maps into the *subuid*
# range, so a host directory owned by the host user is not writable from the
# default identity. Pass `--userns=keep-id` (container uid == host uid).
# Under docker or rootful podman, uid 1000 writes as host uid 1000 directly.
# ---------------------------------------------------------------------------
RUN cat > /opt/box/bin/box-entrypoint <<'EOF'
#!/bin/sh
set -eu

: "${BOX_USER_NAME:=user}"
: "${BOX_USER_HOME:=/home/user}"
: "${BOX_UID:=1000}"
: "${BOX_GID:=1000}"

export HOME="$BOX_USER_HOME"
export USER="$BOX_USER_NAME"

if [ "$(id -u)" = "0" ]; then
  exec setpriv --reuid="$BOX_UID" --regid="$BOX_GID" --init-groups -- "$@"
fi
exec "$@"
EOF
RUN chmod 0755 /opt/box/bin/box-entrypoint

# Image defaults describe the identity the workload actually runs as.
ENV HOME=/home/user \
    USER=user

WORKDIR /home/user/workspace
ENTRYPOINT ["/opt/box/bin/box-entrypoint"]
CMD ["/bin/zsh", "-l"]
