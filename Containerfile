FROM archlinux:latest

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
# ---------------------------------------------------------------------------
ENV MISE_DATA_DIR=/opt/mise/data \
    MISE_CONFIG_DIR=/opt/mise/config \
    MISE_TRUSTED_CONFIG_PATHS=/opt/mise/config

# Build-time identity only; the runtime identity is set at the end of the file.
ENV HOME=/root \
    USER=root \
    PATH=/usr/local/bin:/opt/mise/data/shims:/opt/box/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    STARSHIP_CONFIG=/etc/box/starship.toml

# Unprivileged identity. uid/gid 1000 matches the common single-user host uid,
# so bind-mounted files map 1:1 under `--userns=keep-id` without chowning.
ENV BOX_UID=1000 \
    BOX_GID=1000 \
    BOX_USER_NAME=user \
    BOX_USER_HOME=/home/user

# Arch's own geo mirror: it is what box's default network allowlist permits
# (.pkgbuild.com), so `sudo pacman -S` keeps working inside the VM.
RUN printf '%s\n' 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > /etc/pacman.d/mirrorlist \
 && pacman-key --init || true \
 && pacman-key --populate archlinux || true \
 && pacman -Sy --noconfirm archlinux-keyring \
 && pacman -Syu --noconfirm \
      base-devel \
      ca-certificates \
      clang \
      cmake \
      curl \
      eza \
      fd \
      gdb \
      git \
      github-cli \
      gnupg \
      jq \
      libyaml \
      mise \
      nano \
      ninja \
      openssh \
      python \
      python-pip \
      ripgrep \
      ruby \
      sudo \
      tar \
      unzip \
      util-linux \
      which \
      zsh \
      starship \
 && install -d /opt/mise /opt/box/bin /etc/box \
 && /usr/bin/mise self-update --yes || true \
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
 && rm -rf /var/cache/pacman/pkg/* /root/.cache /root/.local/state/mise \
 && chmod -R a+rX /opt/mise /opt/box \
 && find /opt/mise/data/shims -type f -exec chmod a+rx {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Unprivileged `user` (uid/gid 1000) with passwordless sudo.
# The project bind-mounts at ${BOX_USER_HOME}/workspace, owned by that uid
# so it is writable in user mode without any host-side chown.
# /opt/mise is owned by that uid too: the toolchain lives at a HOME-independent
# path, but `user` must be able to `mise use`/`mise install` into it without
# sudo. root still reads it fine (a+rX).
# ---------------------------------------------------------------------------
RUN groupadd -g "${BOX_GID}" "${BOX_USER_NAME}" 2>/dev/null || true \
 && useradd -m -d "${BOX_USER_HOME}" -u "${BOX_UID}" -g "${BOX_GID}" \
      -s /bin/zsh "${BOX_USER_NAME}" 2>/dev/null || true \
 && usermod -aG wheel "${BOX_USER_NAME}" \
 && printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "${BOX_USER_NAME}" \
      > /etc/sudoers.d/10-box-user \
 && printf '%%wheel ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/11-box-wheel \
 && chmod 0440 /etc/sudoers.d/10-box-user /etc/sudoers.d/11-box-wheel \
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
