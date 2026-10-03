// Package config is box's strict configuration. The embedded resource is
// the schema contract.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nalajala4naresh/box/resources"
)

// LocalOverlayFile is the workspace-local overlay, merged over the global
// user config.
const LocalOverlayFile = "BOXFILE"

// SecretPlaceholder is the guest-visible stand-in for every secret value.
// The guest env var always holds exactly this — never the real value — and
// box's network stack substitutes the real value only on matching traffic
// to the secret's hosts.
const SecretPlaceholder = "NOT-AN-ACTUAL-KEY"

// GuestHome is the unprivileged guest user's home; host-copies land under it
// by default.
const GuestHome = "/home/user"

// localTemplate is the starter content written by `box init`. All
// comments, so it parses as an empty overlay until the user uncomments
// something.
const localTemplate = `# See https://github.com/tobi/box for schema and docs.
# Workspace-local box overrides (BOXFILE).
# Merged over ~/.config/box/config.yml and its config.d/*.yml drop-ins
# using the same schema and merge rules. This file was written by
# ` + "`box init`" + ` and currently changes nothing; uncomment what you need.

# sandbox:
#   image: ghcr.io/tobi/box:desktop

# env:
#   PROJECT_ENV: example

# secrets:
#   - env: EXTRA_TOKEN
#     source: $EXTRA_TOKEN
#     headers:
#       X-Api-Token: $EXTRA_TOKEN
#     hosts:
#       api.example.com: {allow: true}

# network:
#   allow_everything: false
#   allow:
#     - .example.com
#   deny:
#     - ads.example.com
#   ports: [6080]

# agents:
#   - name: pi
#     package: mise:pi@latest
#     host-copy: ~/.pi

# layers:
#   - id: project
#     script: |
#       echo custom project setup
`

// Config is the merged box configuration.
type Config struct {
	Sandbox SandboxConfig     `yaml:"sandbox"`
	Env     map[string]string `yaml:"env"`
	Secrets []SecretSpec      `yaml:"secrets"`
	Network NetworkConfig     `yaml:"network"`
	Agents  []AgentSpec       `yaml:"agents"`
	Layers  []LayerSpec       `yaml:"layers"`
}

// SandboxConfig selects the VM image and its sizing.
type SandboxConfig struct {
	// Image is the OCI image the shared base snapshot is built from.
	Image string `yaml:"image"`
	// CPUs for build and session VMs.
	CPUs uint8 `yaml:"cpus"`
	// Memory is the initial guest memory in MiB.
	Memory uint32 `yaml:"memory"`
	// MemoryMax is the memory ceiling in MiB.
	MemoryMax uint32 `yaml:"memory_max"`
}

// SecretSpec is one host credential scoped to named hosts.
type SecretSpec struct {
	// Env is the guest environment variable name. The guest sees
	// SecretPlaceholder, never the real value.
	Env string `yaml:"env"`
	// Source is exactly one of `$(command)`, `$HOST_VAR`, `file:/path`, or
	// a literal.
	Source string `yaml:"source"`
	// Headers are outgoing header templates carrying the credential, as
	// name → value (e.g. `Authorization: "Bearer $GH_TOKEN"`). Values
	// reference guest env vars holding SecretPlaceholder, which box
	// substitutes on matching traffic. A declared `Authorization` header
	// covering github.com additionally doubles as git's http.extraheader.
	Headers map[string]string `yaml:"headers"`
	// Hosts maps host → `{allow: true}`. Allowed hosts of live secrets fold
	// into the network allowlist; `network.deny` still wins.
	Hosts map[string]HostRule `yaml:"hosts"`
	// Optional skips (instead of aborting) when the source fails to
	// resolve. Use for passthroughs whose host variable may be absent.
	Optional bool `yaml:"optional,omitempty"`
}

// AllowedHosts returns the hosts this secret may reach, sorted.
func (s SecretSpec) AllowedHosts() []string {
	var hosts []string
	for _, host := range sortedKeys(s.Hosts) {
		if s.Hosts[host].Allow {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// HostRule is the per-host policy of a secret.
type HostRule struct {
	Allow bool `yaml:"allow"`
}

// UnmarshalYAML applies the `allow: true` default and rejects unknown keys.
func (r *HostRule) UnmarshalYAML(node *yaml.Node) error {
	r.Allow = true
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: host rule must be a mapping like {allow: true}", node.Line)
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Value != "allow" {
			return fmt.Errorf("line %d: field %s not found in type config.HostRule", key.Line, key.Value)
		}
		if err := value.Decode(&r.Allow); err != nil {
			return err
		}
	}
	return nil
}

// NetworkConfig is the egress policy and published ports.
type NetworkConfig struct {
	AllowEverything bool `yaml:"allow_everything"`
	// Allow is the global egress allowlist. Secret hosts with `allow: true`
	// fold in automatically at policy build time.
	Allow []string `yaml:"allow"`
	// Deny is the global egress denylist (same grammar). It beats `allow`
	// and folded secret hosts.
	Deny []string `yaml:"deny"`
	// Ports are TCP ports published from the guest to the host's loopback,
	// as "HOST:GUEST" or "PORT" (same on both sides).
	Ports []PortSpec `yaml:"ports"`
}

// PortSpec is one published port.
type PortSpec struct {
	Host  uint16
	Guest uint16
}

// MarshalYAML prints a bare number when both sides match.
func (p PortSpec) MarshalYAML() (any, error) {
	if p.Host == p.Guest {
		return int(p.Host), nil
	}
	return fmt.Sprintf("%d:%d", p.Host, p.Guest), nil
}

// UnmarshalYAML accepts `6080`, `"6080"`, or `"5901:5900"`.
func (p *PortSpec) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: port must be a number or \"HOST:GUEST\"", node.Line)
	}
	text := node.Value
	parse := func(s string) (uint16, error) {
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q in %q", s, text)
		}
		return uint16(n), nil
	}
	var host, guest uint16
	var err error
	if h, g, ok := strings.Cut(text, ":"); ok {
		if host, err = parse(h); err != nil {
			return err
		}
		if guest, err = parse(g); err != nil {
			return err
		}
	} else {
		if host, err = parse(text); err != nil {
			return err
		}
		guest = host
	}
	if host == 0 || guest == 0 {
		return errors.New("port must be 1-65535")
	}
	p.Host, p.Guest = host, guest
	return nil
}

// AgentSpec is one coding agent installed into the shared agent layer.
type AgentSpec struct {
	Name     string  `yaml:"name"`
	Package  string  `yaml:"package"`
	HostCopy *string `yaml:"host-copy,omitempty"`
	Guest    *string `yaml:"guest,omitempty"`
}

// LayerSpec is one custom cached shell script layer.
type LayerSpec struct {
	ID     string `yaml:"id"`
	Script string `yaml:"script"`
}

// ResolvedSecret is a live secret with its real host-side value.
type ResolvedSecret struct {
	Env     string
	Value   string
	Headers map[string]string
	Hosts   []string
}

// SortedHeaders returns the declared headers in name order.
func (s ResolvedSecret) SortedHeaders() [][2]string {
	out := make([][2]string, 0, len(s.Headers))
	for _, name := range sortedKeys(s.Headers) {
		out = append(out, [2]string{name, s.Headers[name]})
	}
	return out
}

// ResolvedSecrets splits configured secrets into live ones and skipped
// optionals.
type ResolvedSecrets struct {
	Found []ResolvedSecret
	// Skipped lists optional secrets whose source failed to resolve.
	Skipped []string
}

// ResolvedHostCopy is one opt-in host directory or file imported into a
// project VM.
type ResolvedHostCopy struct {
	Agent string
	Host  string
	Guest string
}

// Default returns the schema defaults for a document that sets nothing.
func Default() Config {
	return Config{
		Sandbox: SandboxConfig{
			Image:     "ghcr.io/tobi/wrap:latest",
			CPUs:      2,
			Memory:    8192,
			MemoryMax: 8192,
		},
	}
}

// Parse strictly decodes one YAML document onto the schema defaults.
// Unknown keys are errors.
func Parse(text string) (Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, err
	}
	return cfg, nil
}

// MustParse is Parse for trusted fixtures.
func MustParse(text string) Config {
	cfg, err := Parse(text)
	if err != nil {
		panic(err)
	}
	return cfg
}

// AllowOutcome is the result of AllowHostInFile.
type AllowOutcome int

const (
	Added AllowOutcome = iota
	AlreadyPresent
)

// ValidateAllowHost validates a `network.allow` entry: an exact host or a
// leading `.` / `*.` wildcard for apex plus subdomains. It rejects URLs,
// paths, and ports, which belong to other keys.
func ValidateAllowHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("host must not be empty")
	}
	if strings.ContainsAny(host, " \t\n\r\v\f") {
		return "", fmt.Errorf("host %q must not contain whitespace", host)
	}
	if strings.Contains(host, "://") || strings.Contains(host, "/") {
		return "", fmt.Errorf("host %q must be a bare host, not a URL", host)
	}
	return host, nil
}

// AllowHostInFile inserts a host into the `network.allow` list of a config
// file, creating nothing else. It is a pure text edit, so every comment and
// the rest of the file survive untouched.
func AllowHostInFile(path, host string) (AllowOutcome, error) {
	host, err := ValidateAllowHost(host)
	if err != nil {
		return 0, err
	}
	// A missing file starts empty, so `box allow --global` on a fresh
	// setup writes a minimal file instead of resurrecting the template.
	text := ""
	if isFile(path) {
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", path, err)
		}
		text = string(data)
	}
	// A fresh `box init` file is comments only, which YAML reads as an
	// empty document: treat it as the default config.
	cfg := Default()
	if substantial(text) {
		if cfg, err = Parse(text); err != nil {
			return 0, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	for _, allowed := range cfg.Network.Allow {
		if allowed == host {
			return AlreadyPresent, nil
		}
	}
	if err := Validate(cfg); err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, []byte(insertAllowEntry(text, host)), 0o644); err != nil {
		return 0, fmt.Errorf("write %s: %w", path, err)
	}
	return Added, nil
}

// insertAllowEntry inserts `    - host` into the `network.allow` list of raw
// YAML text: after the existing items when `allow:` is present, as a new
// `allow:` block when only `network:` is present, or as a new `network:`
// section otherwise.
func insertAllowEntry(text, host string) string {
	lines := splitLines(text)
	networkAt, allowAt := -1, -1
	inNetwork := false
	for index, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inNetwork = strings.HasPrefix(trimmed, "network:")
			if inNetwork {
				networkAt = index
			}
			continue
		}
		if inNetwork && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") &&
			strings.HasPrefix(trimmed, "allow:") {
			allowAt = index
		}
	}
	entry := "    - " + host
	switch {
	case allowAt >= 0:
		if strings.TrimSpace(lines[allowAt]) == "allow: []" {
			lines[allowAt] = "  allow:\n" + entry
		} else {
			insert := allowAt + 1
			for insert < len(lines) &&
				strings.HasPrefix(strings.TrimLeft(lines[insert], " \t"), "- ") &&
				strings.HasPrefix(lines[insert], "    ") {
				insert++
			}
			lines = append(lines[:insert], append([]string{entry}, lines[insert:]...)...)
		}
	case networkAt >= 0:
		lines = append(lines[:networkAt+1], append([]string{"  allow:\n" + entry}, lines[networkAt+1:]...)...)
	default:
		blank := false
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				blank = true
				break
			}
		}
		if !blank {
			lines = append(lines, "")
		}
		lines = append(lines, "network:", "  allow:", entry)
	}
	return strings.Join(lines, "\n") + "\n"
}

// splitLines mirrors Rust's str::lines: no trailing empty element for a
// final newline.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// InitWorkspace writes the workspace-local overlay and exits. It refuses to
// overwrite an existing file and never touches a sandbox.
func InitWorkspace(workspace string) (string, error) {
	path := filepath.Join(workspace, LocalOverlayFile)
	if _, err := os.Lstat(path); err == nil {
		return "", fmt.Errorf("%s already exists; edit it instead", path)
	}
	if err := os.WriteFile(path, []byte(localTemplate), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// ConfigDir is `$XDG_CONFIG_HOME/box`, defaulting to `~/.config/box` on
// every platform so the documented paths hold on macOS too.
func ConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "box")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "box")
	}
	return filepath.Join(home, ".config", "box")
}

// ConfigPath is the global user config file.
func ConfigPath() string {
	return filepath.Join(ConfigDir(), "config.yml")
}

// EnsureConfigDir creates the parent directory of a global config path
// without creating the file itself.
func EnsureConfigDir(path string) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create config directory %s: %w", parent, err)
	}
	return nil
}

// EnsureUserConfig writes the commented template when no user config exists
// yet. It never overwrites an existing file and reports whether it wrote.
func EnsureUserConfig(path string) (bool, error) {
	if _, err := os.Lstat(path); err == nil {
		return false, nil
	}
	if err := EnsureConfigDir(path); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, []byte(commentedDefaultTemplate()), 0o644); err != nil {
		return false, fmt.Errorf("write new config %s: %w", path, err)
	}
	return true, nil
}

// commentedDefaultTemplate is the entire embedded default set with every
// value commented out, so the file documents the schema while parsing as
// pure defaults. Generated from the embedded defaults so it cannot drift.
func commentedDefaultTemplate() string {
	var out strings.Builder
	out.WriteString("# box configuration — ~/.config/box/config.yml\n" +
		"#\n" +
		"# Written on first run. Every default below is commented out, so\n" +
		"# this file changes nothing: uncomment a line to override it.\n" +
		"# Personal overrides live better in config.d/*.yml next to this\n" +
		"# file (lexical order, e.g. 10-shopify.yml); keep this file for\n" +
		"# small global tweaks. This file is never overwritten.\n" +
		"#\n" +
		"# Precedence (later wins):\n" +
		"#   embedded defaults → this file → config.d/*.yml\n" +
		"#   → BOXFILE in the workspace → --config PATH / $BOX_CONFIG.\n")
	for _, line := range splitLines(resources.DefaultYAML) {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			out.WriteString("# ")
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	return out.String()
}

// ConfigDDir is the drop-in directory next to the user config.
func ConfigDDir(user string) string {
	return filepath.Join(filepath.Dir(user), "config.d")
}

type overlayFile struct {
	path string
	text string
}

func configDOverlays(user string) ([]overlayFile, error) {
	dir := ConfigDDir(user)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	var files []string
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		ext := filepath.Ext(path)
		if isFile(path) && (ext == ".yml" || ext == ".yaml") {
			files = append(files, path)
		}
	}
	sort.Strings(files)
	overlays := make([]overlayFile, 0, len(files))
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		// Surface a broken drop-in with its filename instead of a generic
		// merged-overlay error.
		var probe any
		if err := yaml.Unmarshal(data, &probe); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		overlays = append(overlays, overlayFile{path: path, text: string(data)})
	}
	return overlays, nil
}

// Source is one layer in the merge stack. An empty Path is the embedded
// defaults.
type Source struct {
	Path string
}

// Label is home-relative when possible (`~/.config/box/config.yml`).
func (s Source) Label() string {
	if s.Path == "" {
		return "embedded defaults"
	}
	return ShortenHome(s.Path)
}

// ShortenHome rewrites a path under $HOME as `~/...`.
func ShortenHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return path
	}
	if rel == "." {
		return "~"
	}
	return "~/" + rel
}

// Loaded is the merged config plus the files that produced it.
type Loaded struct {
	Config  Config
	Sources []Source
}

// LoadFull loads the merged config for a workspace:
//
// embedded defaults → user config (created on first run) →
// `<config-dir>/config.d/*.yml` (lexical order) → `<workspace>/BOXFILE` →
// explicit `--config` / `BOX_CONFIG` path.
func LoadFull(workspace, explicit string) (Loaded, error) {
	return loadFromPaths(ConfigPath(), workspace, explicit)
}

func loadFromPaths(user, workspace, explicit string) (Loaded, error) {
	if _, err := EnsureUserConfig(user); err != nil {
		return Loaded{}, err
	}
	sources := []Source{{}}
	var overlays []string
	if isFile(user) {
		data, err := os.ReadFile(user)
		if err != nil {
			return Loaded{}, fmt.Errorf("read %s: %w", user, err)
		}
		overlays = append(overlays, string(data))
		sources = append(sources, Source{Path: user})
	}
	dropIns, err := configDOverlays(user)
	if err != nil {
		return Loaded{}, err
	}
	for _, overlay := range dropIns {
		overlays = append(overlays, overlay.text)
		sources = append(sources, Source{Path: overlay.path})
	}
	local := filepath.Join(workspace, LocalOverlayFile)
	if isFile(local) {
		data, err := os.ReadFile(local)
		if err != nil {
			return Loaded{}, fmt.Errorf("read %s: %w", local, err)
		}
		overlays = append(overlays, string(data))
		sources = append(sources, Source{Path: local})
	}
	if explicit != "" {
		data, err := os.ReadFile(explicit)
		if err != nil {
			return Loaded{}, fmt.Errorf("read explicit config %s: %w", explicit, err)
		}
		overlays = append(overlays, string(data))
		sources = append(sources, Source{Path: explicit})
	}
	cfg, err := MergeConfigs(overlays)
	if err != nil {
		return Loaded{}, fmt.Errorf("parse merged box config: %w", err)
	}
	if err := Validate(cfg); err != nil {
		return Loaded{}, err
	}
	return Loaded{Config: cfg, Sources: sources}, nil
}

// ToYAML renders the effective config after every overlay has merged.
// Secret sources stay as written; resolved values never appear.
func ToYAML(cfg Config) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(normalize(cfg)); err != nil {
		return "", fmt.Errorf("serialize box config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("serialize box config: %w", err)
	}
	return buf.String(), nil
}

// normalize turns nil collections into empty ones so the dump always shows
// every key, matching the schema.
func normalize(cfg Config) Config {
	if cfg.Env == nil {
		cfg.Env = map[string]string{}
	}
	if cfg.Secrets == nil {
		cfg.Secrets = []SecretSpec{}
	}
	for i := range cfg.Secrets {
		if cfg.Secrets[i].Headers == nil {
			cfg.Secrets[i].Headers = map[string]string{}
		}
		if cfg.Secrets[i].Hosts == nil {
			cfg.Secrets[i].Hosts = map[string]HostRule{}
		}
	}
	if cfg.Network.Allow == nil {
		cfg.Network.Allow = []string{}
	}
	if cfg.Network.Deny == nil {
		cfg.Network.Deny = []string{}
	}
	if cfg.Network.Ports == nil {
		cfg.Network.Ports = []PortSpec{}
	}
	if cfg.Agents == nil {
		cfg.Agents = []AgentSpec{}
	}
	if cfg.Layers == nil {
		cfg.Layers = []LayerSpec{}
	}
	return cfg
}

// MergeConfigs merges overlay documents over the embedded defaults.
func MergeConfigs(overlays []string) (Config, error) {
	var merged any
	if err := yaml.Unmarshal([]byte(resources.DefaultYAML), &merged); err != nil {
		return Config{}, fmt.Errorf("parse embedded resources/default.yml: %w", err)
	}
	for _, text := range overlays {
		if strings.TrimSpace(text) == "" {
			continue
		}
		var overlay any
		if err := yaml.Unmarshal([]byte(text), &overlay); err != nil {
			// A comments-only file is an empty document; any document with
			// real content still reports its syntax error.
			if substantial(text) {
				return Config{}, fmt.Errorf("parse config overlay YAML: %w", err)
			}
			continue
		}
		if overlay == nil {
			continue
		}
		var err error
		if merged, err = mergeValue(merged, overlay, ""); err != nil {
			return Config{}, err
		}
	}
	data, err := yaml.Marshal(merged)
	if err != nil {
		return Config{}, fmt.Errorf("deserialize merged config: %w", err)
	}
	cfg, err := Parse(string(data))
	if err != nil {
		return Config{}, fmt.Errorf("deserialize merged config: %w", err)
	}
	return cfg, nil
}

func mergeValue(base, overlay any, field string) (any, error) {
	if identity := identityField(field); identity != "" {
		return mergeKeyedSequence(base, overlay, identity)
	}
	baseMap, baseIsMap := base.(map[string]any)
	overlayMap, overlayIsMap := overlay.(map[string]any)
	if baseIsMap && overlayIsMap {
		for _, key := range sortedKeys(overlayMap) {
			value := overlayMap[key]
			if current, ok := baseMap[key]; ok {
				next, err := mergeValue(current, value, key)
				if err != nil {
					return nil, err
				}
				baseMap[key] = next
			} else {
				baseMap[key] = value
			}
		}
		return baseMap, nil
	}
	baseSeq, baseIsSeq := base.([]any)
	overlaySeq, overlayIsSeq := overlay.([]any)
	if baseIsSeq && overlayIsSeq && (field == "allow" || field == "deny") {
		// `network.allow` / `network.deny` merge additively: entries append,
		// duplicates drop. Blocking a default-allowed host stays expressible
		// because `deny` wins over `allow`.
		for _, item := range overlaySeq {
			if !containsValue(baseSeq, item) {
				baseSeq = append(baseSeq, item)
			}
		}
		return baseSeq, nil
	}
	return overlay, nil
}

func identityField(field string) string {
	switch field {
	case "agents":
		return "name"
	case "layers":
		return "id"
	case "secrets":
		return "env"
	}
	return ""
}

func mergeKeyedSequence(base, overlay any, identity string) (any, error) {
	patches, ok := overlay.([]any)
	if !ok {
		return overlay, nil
	}
	if len(patches) == 0 {
		return []any{}, nil
	}
	items, ok := base.([]any)
	if !ok {
		return patches, nil
	}
	for _, patch := range patches {
		patchMap, _ := patch.(map[string]any)
		value, ok := patchMap[identity].(string)
		if !ok {
			return nil, fmt.Errorf("overlay entry in keyed list must have %s", identity)
		}
		found := false
		for i, item := range items {
			itemMap, _ := item.(map[string]any)
			if current, _ := itemMap[identity].(string); itemMap != nil && current == value {
				merged, err := mergeValue(item, patch, "")
				if err != nil {
					return nil, err
				}
				items[i] = merged
				found = true
				break
			}
		}
		if !found {
			items = append(items, patch)
		}
	}
	return items, nil
}

func containsValue(items []any, item any) bool {
	for _, existing := range items {
		if reflect.DeepEqual(existing, item) {
			return true
		}
	}
	return false
}

// EffectiveAllowHosts is `network.allow` plus the hosts of live (resolved)
// secrets. Secrets that failed to resolve whitelist nothing. `network.deny`
// wins on exact-match conflicts.
func EffectiveAllowHosts(cfg Config, secrets ResolvedSecrets) []string {
	var allow []string
	add := func(host string) {
		for _, existing := range allow {
			if existing == host {
				return
			}
		}
		allow = append(allow, host)
	}
	for _, host := range cfg.Network.Allow {
		add(host)
	}
	for _, secret := range secrets.Found {
		for _, host := range secret.Hosts {
			add(host)
		}
	}
	kept := allow[:0]
	for _, host := range allow {
		denied := false
		for _, deny := range cfg.Network.Deny {
			if deny == host {
				denied = true
				break
			}
		}
		if !denied {
			kept = append(kept, host)
		}
	}
	return kept
}

// IsHostReachable reports whether host may egress under the effective
// policy: covered by the allowlist and not beaten by `deny`. It mirrors the
// rule compilation the network stack enforces, so `box log` judges guest
// DNS lookups by the same semantics.
func IsHostReachable(cfg Config, secrets ResolvedSecrets, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	allowed := false
	for _, rule := range EffectiveAllowHosts(cfg, secrets) {
		if NetworkRuleMatches(rule, host) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	for _, rule := range cfg.Network.Deny {
		if NetworkRuleMatches(rule, host) {
			return false
		}
	}
	return true
}

// NetworkRuleMatches checks one allow/deny entry against a queried host.
// Exact entries match only themselves; a leading `.` or `*.` entry covers
// its apex plus all subdomains.
func NetworkRuleMatches(rule, host string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	apex, isSuffix := strings.CutPrefix(rule, "*.")
	if !isSuffix {
		apex, isSuffix = strings.CutPrefix(rule, ".")
	}
	if isSuffix {
		return host == apex || strings.HasSuffix(host, "."+apex)
	}
	return host == rule
}

// Validate enforces the invariants serde cannot express.
func Validate(cfg Config) error {
	if cfg.Sandbox.CPUs == 0 {
		return errors.New("sandbox.cpus must be greater than zero")
	}
	if cfg.Sandbox.Memory == 0 {
		return errors.New("sandbox.memory must be greater than zero")
	}
	if cfg.Sandbox.MemoryMax < cfg.Sandbox.Memory {
		return fmt.Errorf("sandbox.memory_max (%d) must be at least sandbox.memory (%d)",
			cfg.Sandbox.MemoryMax, cfg.Sandbox.Memory)
	}

	secretNames := map[string]bool{}
	for _, secret := range cfg.Secrets {
		if err := validateEnvName(secret.Env); err != nil {
			return fmt.Errorf("invalid secret env %s: %w", secret.Env, err)
		}
		if secretNames[secret.Env] {
			return fmt.Errorf("duplicate secret env %s", secret.Env)
		}
		secretNames[secret.Env] = true
		if strings.TrimSpace(secret.Source) == "" {
			return fmt.Errorf("secret %s source must not be empty", secret.Env)
		}
		for _, name := range sortedKeys(secret.Headers) {
			value := secret.Headers[name]
			if strings.TrimSpace(name) == "" || !isIdent(name, "-_") {
				return fmt.Errorf("secret %s has an invalid header name %q", secret.Env, name)
			}
			if strings.TrimSpace(value) == "" || strings.ContainsFunc(value, func(c rune) bool {
				return c == '"' || c < 0x20 || c == 0x7f
			}) {
				return fmt.Errorf("secret %s header %s value must not be empty", secret.Env, name)
			}
		}
		for host := range secret.Hosts {
			if strings.TrimSpace(host) == "" {
				return fmt.Errorf("secret %s has an empty host", secret.Env)
			}
		}
	}

	agentNames := map[string]bool{}
	for _, agent := range cfg.Agents {
		if agent.Name == "" || !isIdent(agent.Name, "-_") {
			return fmt.Errorf("invalid agent name %s", agent.Name)
		}
		if agentNames[agent.Name] {
			return fmt.Errorf("duplicate agent name %s", agent.Name)
		}
		agentNames[agent.Name] = true
		if _, err := MisePackage(agent.Package); err != nil {
			return fmt.Errorf("invalid package for agent %s: %w", agent.Name, err)
		}
		if agent.Guest != nil && !strings.HasPrefix(*agent.Guest, "/") {
			return fmt.Errorf("agent %s guest path must be absolute", agent.Name)
		}
	}

	layerIDs := map[string]bool{}
	for _, layer := range cfg.Layers {
		if layer.ID == "" {
			return errors.New("layer id must not be empty")
		}
		if layerIDs[layer.ID] {
			return fmt.Errorf("duplicate layer id %s", layer.ID)
		}
		layerIDs[layer.ID] = true
	}
	return nil
}

func validateEnvName(name string) error {
	if name == "" || !(name[0] == '_' || isAlpha(name[0])) || !isIdent(name, "_") {
		return errors.New("expected an environment variable name")
	}
	return nil
}

func isIdent(s, extra string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(isAlpha(c) || (c >= '0' && c <= '9') || strings.IndexByte(extra, c) >= 0) {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// MisePackage validates an agent package locator and returns the mise spec.
func MisePackage(pkg string) (string, error) {
	var spec string
	switch {
	case strings.HasPrefix(pkg, "mise:"):
		spec = strings.TrimPrefix(pkg, "mise:")
	case strings.HasPrefix(pkg, "github:"):
		spec = pkg
	default:
		return "", errors.New("unsupported package source; expected mise:<tool>@<version> or github:<owner>/<repo>@<version>")
	}
	if spec == "" || strings.HasPrefix(spec, "-") || strings.ContainsAny(spec, " \t\n\r\v\f") {
		return "", fmt.Errorf("invalid package %s", pkg)
	}
	return spec, nil
}

// ResolveSecrets resolves every secret source on the host. Optional secrets
// that fail are skipped; required ones abort.
func ResolveSecrets(cfg Config) (ResolvedSecrets, error) {
	resolved := ResolvedSecrets{}
	for _, spec := range cfg.Secrets {
		value, err := resolveHostValue(spec.Source)
		switch {
		case err == nil:
			resolved.Found = append(resolved.Found, ResolvedSecret{
				Env:     spec.Env,
				Value:   value,
				Headers: spec.Headers,
				Hosts:   spec.AllowedHosts(),
			})
		case spec.Optional:
			resolved.Skipped = append(resolved.Skipped, spec.Env)
		default:
			return ResolvedSecrets{}, fmt.Errorf("import secret %s from source: %w; "+
				"fix the source, or set `optional: true` for %s in %s to skip it when unavailable",
				spec.Env, err, spec.Env, ShortenHome(filepath.Join(ConfigDDir(ConfigPath()), "*.yml")))
		}
	}
	return resolved, nil
}

// ResolveHostCopies resolves every agent's opt-in host-copy.
func ResolveHostCopies(cfg Config, home string) ([]ResolvedHostCopy, error) {
	var copies []ResolvedHostCopy
	for _, agent := range cfg.Agents {
		if agent.HostCopy == nil {
			continue
		}
		value, err := resolveHostValue(*agent.HostCopy)
		if err != nil {
			return nil, fmt.Errorf("resolve agent %s host-copy: %w", agent.Name, err)
		}
		host := expandTilde(value, home)
		if _, err := os.Stat(host); err != nil {
			return nil, fmt.Errorf("agent %s host-copy does not exist: %s", agent.Name, host)
		}
		guest := ""
		if agent.Guest != nil {
			guest = *agent.Guest
		} else {
			name := filepath.Base(host)
			if name == "/" || name == "." {
				return nil, fmt.Errorf("derive guest path from host-copy %s", host)
			}
			guest = GuestHome + "/" + name
		}
		copies = append(copies, ResolvedHostCopy{Agent: agent.Name, Host: host, Guest: guest})
	}
	return copies, nil
}

func resolveHostValue(raw string) (string, error) {
	if command, ok := strings.CutPrefix(raw, "$("); ok {
		command, ok = strings.CutSuffix(command, ")")
		if !ok {
			return "", errors.New("unterminated $(command)")
		}
		if strings.TrimSpace(command) == "" {
			return "", errors.New("empty $(command)")
		}
		cmd := exec.Command("/bin/sh", "-c", command)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				return "", fmt.Errorf("run host command %q: %w", command, err)
			}
			detail := strings.TrimSpace(stderr.String())
			if detail == "" {
				return "", fmt.Errorf("host command %q exited %s", command, exitErr.ProcessState)
			}
			return "", fmt.Errorf("host command %q exited %s: %s", command, exitErr.ProcessState, detail)
		}
		value := strings.TrimSpace(stdout.String())
		if value == "" {
			return "", fmt.Errorf("host command %q returned an empty value", command)
		}
		return value, nil
	}

	if name, ok := strings.CutPrefix(raw, "$"); ok {
		if err := validateEnvName(name); err != nil {
			return "", fmt.Errorf("invalid $ENVIRONMENT host value: %w", err)
		}
		value, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("host environment variable %s is not set", name)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf("host environment variable %s is empty", name)
		}
		return value, nil
	}

	if path, ok := strings.CutPrefix(raw, "file:"); ok {
		path = strings.TrimSpace(path)
		if path == "" {
			return "", errors.New("file: host value must name a path")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("home directory: %w", err)
		}
		path = expandTilde(path, home)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read secret file %s: %w", path, err)
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", fmt.Errorf("secret file %s is empty", path)
		}
		return value, nil
	}

	if raw == "" {
		return "", errors.New("literal host value must not be empty")
	}
	return raw, nil
}

func expandTilde(path, home string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return filepath.Join(home, rest)
	}
	if path == "~" {
		return home
	}
	return path
}

func substantial(text string) bool {
	for _, line := range splitLines(text) {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return true
		}
	}
	return false
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
