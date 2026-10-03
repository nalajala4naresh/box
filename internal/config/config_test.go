package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/nalajala4naresh/box/resources"
)

func secretEnvs(cfg Config) []string {
	var envs []string
	for _, secret := range cfg.Secrets {
		envs = append(envs, secret.Env)
	}
	return envs
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func testDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParsesEmbeddedDefaultVerbatimContract(t *testing.T) {
	cfg := MustParse(resources.DefaultYAML)
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.Image != "ghcr.io/tobi/wrap:latest" || cfg.Sandbox.CPUs != 2 ||
		cfg.Sandbox.Memory != 8192 || cfg.Sandbox.MemoryMax != 8192 {
		t.Fatalf("sandbox defaults: %+v", cfg.Sandbox)
	}
	want := []string{"GH_TOKEN", "OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"}
	if got := secretEnvs(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("secrets %v", got)
	}
	github := cfg.Secrets[0]
	if github.Source != "$(gh auth token)" || github.Headers["Authorization"] != "Bearer $GH_TOKEN" || github.Optional {
		t.Fatalf("github secret %+v", github)
	}
	if _, ok := github.Hosts["github.com"]; !ok {
		t.Fatal("github.com host")
	}
	if _, ok := github.Hosts["api.github.com"]; !ok {
		t.Fatal("api.github.com host")
	}
	for _, secret := range cfg.Secrets[1:] {
		if !secret.Optional {
			t.Fatalf("%s must be an optional passthrough", secret.Env)
		}
		if len(secret.Headers) != 1 || len(secret.AllowedHosts()) != 1 {
			t.Fatalf("%s headers/hosts", secret.Env)
		}
	}
	if cfg.Secrets[3].Headers["X-Api-Key"] != "$ANTHROPIC_API_KEY" {
		t.Fatal("anthropic header")
	}
	if cfg.Agents[0].Package != "mise:pi@latest" {
		t.Fatal("pi package")
	}
	for _, agent := range cfg.Agents {
		if agent.HostCopy != nil {
			t.Fatalf("%s host-copy must be opt-in", agent.Name)
		}
		if agent.Name == "try" {
			t.Fatal("try ships commented out")
		}
	}
	if len(cfg.Layers) != 2 || cfg.Layers[0].ID != "packages" || cfg.Layers[1].ID != "dotfiles" {
		t.Fatalf("layers %+v", cfg.Layers)
	}
}

func TestFirstRunWritesCommentedDefaultsWithoutChangingThem(t *testing.T) {
	dir := testDir(t, "first-run")
	user := filepath.Join(dir, "box", "config.yml")
	workspace := filepath.Join(dir, "work")
	os.MkdirAll(workspace, 0o755)
	wrote, err := EnsureUserConfig(user)
	if err != nil || !wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	var probe any
	if err := yaml.Unmarshal([]byte(read(t, user)), &probe); err != nil || probe != nil {
		t.Fatalf("template must parse as an empty document: %v %v", probe, err)
	}
	loaded, err := loadFromPaths(user, workspace, "")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Config.Sandbox.Image != "ghcr.io/tobi/wrap:latest" || secretEnvs(loaded.Config)[0] != "GH_TOKEN" {
		t.Fatal("defaults changed")
	}
	if !reflect.DeepEqual(loaded.Sources, []Source{{}, {Path: user}}) {
		t.Fatalf("sources %v", loaded.Sources)
	}
	if wrote, _ := EnsureUserConfig(user); wrote {
		t.Fatal("existing file must never be overwritten")
	}
}

func TestRejectsLegacyAndUnknownKeys(t *testing.T) {
	_, err := Parse("base_image: archlinux\n")
	if err == nil || !strings.Contains(err.Error(), "base_image") {
		t.Fatalf("err %v", err)
	}
	for _, text := range []string{
		"image: ghcr.io/tobi/wrap:latest\n",
		"build:\n  cpus: 4\n",
		"network:\n  allow_host: [example.com]\n",
		"network:\n  deny_host: [example.com]\n",
		"secrets:\n  - env: X\n    host-env: $X\n",
		"secrets:\n  - env: X\n    source: $X\n    placeholder: $MSB_X\n",
		"secrets:\n  - env: X\n    source: $X\n    bearer: true\n",
		"secrets:\n  - env: X\n    source: $X\n    hosts:\n      a.com: {allow: true, extra: 1}\n",
	} {
		if _, err := Parse(text); err == nil {
			t.Fatalf("legacy shape must be rejected: %q", text)
		}
	}
}

func TestParsesPortSpecs(t *testing.T) {
	cfg := MustParse("network:\n  ports: [6080, '5901:5900', ' 9222 ']\n")
	want := []PortSpec{{6080, 6080}, {5901, 5900}, {9222, 9222}}
	if !reflect.DeepEqual(cfg.Network.Ports, want) {
		t.Fatalf("ports %v", cfg.Network.Ports)
	}
	for _, bad := range []string{"network:\n  ports: ['0']\n", "network:\n  ports: ['a:b']\n"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("must reject %q", bad)
		}
	}
}

func TestSandboxIsSelectableWithADefault(t *testing.T) {
	cfg := MustParse("sandbox:\n  image: ghcr.io/tobi/box:desktop\n")
	if cfg.Sandbox.Image != "ghcr.io/tobi/box:desktop" || cfg.Sandbox.CPUs != 2 {
		t.Fatalf("%+v", cfg.Sandbox)
	}
}

func TestResolvesAllThreeHostValueForms(t *testing.T) {
	if v, _ := resolveHostValue("literal"); v != "literal" {
		t.Fatal(v)
	}
	if v, err := resolveHostValue("$(printf command)"); v != "command" {
		t.Fatal(v, err)
	}
	_, err := resolveHostValue("$BOX_TEST_VARIABLE_THAT_MUST_NOT_EXIST")
	if err == nil || !strings.Contains(err.Error(), "is not set") {
		t.Fatal(err)
	}
}

func TestResolvesFileHostValues(t *testing.T) {
	dir := testDir(t, "secret-file")
	path := filepath.Join(dir, "token")
	write(t, path, "  file-token\n")
	if v, err := resolveHostValue("file:" + path); v != "file-token" {
		t.Fatal(v, err)
	}
	if _, err := resolveHostValue("file:"); err == nil {
		t.Fatal("empty file: must fail")
	}
	if _, err := resolveHostValue("file:" + filepath.Join(dir, "absent")); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestFailedAndEmptySecretCommandsAreFatal(t *testing.T) {
	_, err := resolveHostValue("$(printf denied >&2; exit 7)")
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatal(err)
	}
	_, err = resolveHostValue("$(printf '')")
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Fatal(err)
	}
}

func TestSupportedPackagePrefixesAreExplicit(t *testing.T) {
	if v, _ := MisePackage("mise:pi@latest"); v != "pi@latest" {
		t.Fatal(v)
	}
	if v, _ := MisePackage("github:can1357/oh-my-pi@latest"); v != "github:can1357/oh-my-pi@latest" {
		t.Fatal(v)
	}
	if _, err := MisePackage("npm:pi@latest"); err == nil {
		t.Fatal("npm must fail")
	}
	if _, err := MisePackage("mise:--help"); err == nil {
		t.Fatal("option must fail")
	}
}

func TestMergesKeyedMinimalOverlay(t *testing.T) {
	cfg, err := MergeConfigs([]string{
		"agents:\n  - name: omp\n    package: github:can1357/oh-my-pi@latest\n" +
			"layers:\n  - id: dotfiles\n    script: echo actual\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.MemoryMax != 8192 || len(cfg.Secrets) != 4 || len(cfg.Agents) != 4 || len(cfg.Layers) != 2 {
		t.Fatalf("%+v", cfg)
	}
	for _, agent := range cfg.Agents {
		if agent.Name == "omp" && (agent.Package != "github:can1357/oh-my-pi@latest" || agent.HostCopy != nil) {
			t.Fatalf("omp %+v", agent)
		}
	}
	if !strings.Contains(cfg.Layers[1].Script, "echo actual") {
		t.Fatal(cfg.Layers[1].Script)
	}
}

func TestEmptyKeyedListClearsDefault(t *testing.T) {
	cfg, err := MergeConfigs([]string{"agents: []\n"})
	if err != nil || len(cfg.Agents) != 0 {
		t.Fatal(cfg.Agents, err)
	}
}

func TestConfigSourceLabelsShortenHome(t *testing.T) {
	if (Source{}).Label() != "embedded defaults" {
		t.Fatal("embedded label")
	}
	if home, err := os.UserHomeDir(); err == nil {
		if got := (Source{Path: filepath.Join(home, ".config/box/config.yml")}).Label(); got != "~/.config/box/config.yml" {
			t.Fatal(got)
		}
	}
	if got := (Source{Path: "/tmp/BOXFILE"}).Label(); got != "/tmp/BOXFILE" {
		t.Fatal(got)
	}
}

func TestDumpsMergedConfigWithoutDefaultHostCopy(t *testing.T) {
	cfg, _ := MergeConfigs(nil)
	text, err := ToYAML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "host-copy") || !strings.Contains(text, "name: pi") ||
		!strings.Contains(text, "$(gh auth token)") || strings.Contains(text, "NOT-AN-ACTUAL-KEY") {
		t.Fatal(text)
	}
	again, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(again); err != nil {
		t.Fatal(err)
	}
	if len(again.Agents) != 4 || again.Sandbox.Image != cfg.Sandbox.Image || len(again.Secrets) != len(cfg.Secrets) {
		t.Fatal("round trip changed the config")
	}
}

func TestDumpsOverlayHostCopyAndSplitPorts(t *testing.T) {
	cfg, err := MergeConfigs([]string{"agents:\n  - name: pi\n    host-copy: ~/.pi\n" +
		"network:\n  ports: [6080, '5901:5900']\n"})
	if err != nil {
		t.Fatal(err)
	}
	text, _ := ToYAML(cfg)
	if !strings.Contains(text, "host-copy: ~/.pi") || !strings.Contains(text, "6080") || !strings.Contains(text, "5901:5900") {
		t.Fatal(text)
	}
	again := MustParse(text)
	if *again.Agents[0].HostCopy != "~/.pi" {
		t.Fatal("host-copy lost")
	}
	if !reflect.DeepEqual(again.Network.Ports, []PortSpec{{6080, 6080}, {5901, 5900}}) {
		t.Fatal(again.Network.Ports)
	}
}

func TestAllowCreatesMinimalGlobalFileWhenMissing(t *testing.T) {
	dir := testDir(t, "allow-creates")
	path := filepath.Join(dir, "box", "config.yml")
	EnsureConfigDir(path)
	if outcome, err := AllowHostInFile(path, ".example.com"); err != nil || outcome != Added {
		t.Fatal(outcome, err)
	}
	text := read(t, path)
	if !strings.Contains(text, ".example.com") || strings.Contains(text, "GH_TOKEN") {
		t.Fatal(text)
	}
	if outcome, _ := AllowHostInFile(path, ".example.com"); outcome != AlreadyPresent {
		t.Fatal("second run must report presence")
	}
}

func TestOverlayPrecedenceRunsUserThenWorkspaceThenExplicit(t *testing.T) {
	dir := testDir(t, "precedence")
	user := filepath.Join(dir, "user.yml")
	workspace := filepath.Join(dir, "ws")
	write(t, user, "sandbox:\n  image: user-image\n")
	write(t, filepath.Join(workspace, LocalOverlayFile), "sandbox:\n  image: workspace-image\n")
	loaded, err := loadFromPaths(user, workspace, "")
	if err != nil || loaded.Config.Sandbox.Image != "workspace-image" {
		t.Fatal(loaded.Config.Sandbox.Image, err)
	}
	explicit := filepath.Join(dir, "explicit.yml")
	write(t, explicit, "sandbox:\n  image: explicit-image\n")
	loaded, err = loadFromPaths(user, workspace, explicit)
	if err != nil || loaded.Config.Sandbox.Image != "explicit-image" {
		t.Fatal(loaded.Config.Sandbox.Image, err)
	}
	want := []Source{{}, {Path: user}, {Path: filepath.Join(workspace, LocalOverlayFile)}, {Path: explicit}}
	if !reflect.DeepEqual(loaded.Sources, want) {
		t.Fatal(loaded.Sources)
	}
	bare := filepath.Join(dir, "bare")
	os.MkdirAll(bare, 0o755)
	loaded, _ = loadFromPaths(user, bare, "")
	if loaded.Config.Sandbox.Image != "user-image" {
		t.Fatal(loaded.Config.Sandbox.Image)
	}
	if _, err := loadFromPaths(user, bare, filepath.Join(dir, "absent.yml")); err == nil {
		t.Fatal("missing explicit path must be a hard error")
	}
}

func TestConfigDDropInsMergeInLexicalOrder(t *testing.T) {
	dir := testDir(t, "config-d")
	user := filepath.Join(dir, "config.yml")
	workspace := filepath.Join(dir, "work")
	os.MkdirAll(workspace, 0o755)
	write(t, user, "sandbox:\n  image: user-image\n  cpus: 2\n")
	dropIns := filepath.Join(dir, "config.d")
	write(t, filepath.Join(dropIns, "20-second.yml"), "sandbox:\n  image: second-image\n")
	write(t, filepath.Join(dropIns, "10-first.yml"), "sandbox:\n  image: first-image\n")
	write(t, filepath.Join(dropIns, "notes.txt"), "sandbox:\n  image: ignored\n")
	write(t, filepath.Join(dropIns, "15-mid.yaml"), "sandbox:\n  cpus: 4\n")
	loaded, err := loadFromPaths(user, workspace, "")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Config.Sandbox.Image != "second-image" || loaded.Config.Sandbox.CPUs != 4 {
		t.Fatalf("%+v", loaded.Config.Sandbox)
	}
	want := []Source{{}, {Path: user},
		{Path: filepath.Join(dropIns, "10-first.yml")},
		{Path: filepath.Join(dropIns, "15-mid.yaml")},
		{Path: filepath.Join(dropIns, "20-second.yml")}}
	if !reflect.DeepEqual(loaded.Sources, want) {
		t.Fatal(loaded.Sources)
	}
	write(t, filepath.Join(workspace, LocalOverlayFile), "sandbox:\n  image: workspace-image\n")
	loaded, _ = loadFromPaths(user, workspace, "")
	if loaded.Config.Sandbox.Image != "workspace-image" {
		t.Fatal(loaded.Config.Sandbox.Image)
	}
}

func TestConfigDBrokenFileFailsWithItsPath(t *testing.T) {
	dir := testDir(t, "config-d-broken")
	user := filepath.Join(dir, "config.yml")
	workspace := filepath.Join(dir, "work")
	os.MkdirAll(workspace, 0o755)
	write(t, user, "sandbox:\n  image: user-image\n")
	write(t, filepath.Join(dir, "config.d", "10-broken.yml"), "sandbox:\n  image: [unclosed\n")
	_, err := loadFromPaths(user, workspace, "")
	if err == nil || !strings.Contains(err.Error(), "10-broken.yml") {
		t.Fatalf("error names the drop-in: %v", err)
	}
}

func TestSecretHostsFoldIntoTheNetworkAllowlist(t *testing.T) {
	cfg := MustParse("network:\n  allow: [example.com]\n" +
		"secrets:\n  - env: TEST_TOKEN\n    source: literal\n    hosts:\n      api.example.com: {allow: true}\n")
	resolved, _ := ResolveSecrets(cfg)
	allow := EffectiveAllowHosts(cfg, resolved)
	if !contains(allow, "example.com") || !contains(allow, "api.example.com") {
		t.Fatal(allow)
	}
}

func TestDenyBeatsAllowAndFoldedSecretHosts(t *testing.T) {
	cfg := MustParse("network:\n  allow: [blocked.example.com, open.example.com]\n  deny: [blocked.example.com, secret.example.com]\n" +
		"secrets:\n  - env: TEST_TOKEN\n    source: literal\n    hosts:\n      secret.example.com: {allow: true}\n      open.example.com: {allow: true}\n")
	resolved, _ := ResolveSecrets(cfg)
	allow := EffectiveAllowHosts(cfg, resolved)
	if contains(allow, "blocked.example.com") || contains(allow, "secret.example.com") || !contains(allow, "open.example.com") {
		t.Fatal(allow)
	}
}

func TestReachabilityJudgesExactSuffixAndDeny(t *testing.T) {
	cfg := MustParse("network:\n  allow: [exact.example.com, .suffix.example.com, '*.wild.example.com']\n" +
		"  deny: [blocked.example.com, .denied.example.com, deep.suffix.example.com]\n")
	resolved, _ := ResolveSecrets(cfg)
	cases := map[string]bool{
		"exact.example.com":       true,
		"sub.exact.example.com":   false,
		"suffix.example.com":      true,
		"deep.suffix.example.com": false,
		"wild.example.com":        true,
		"a.wild.example.com":      true,
		"other.example.com":       false,
		"blocked.example.com":     false,
		"denied.example.com":      false,
		"x.denied.example.com":    false,
		"EXACT.EXAMPLE.COM.":      true,
		"":                        false,
	}
	for host, want := range cases {
		if got := IsHostReachable(cfg, resolved, host); got != want {
			t.Errorf("%q: got %v want %v", host, got, want)
		}
	}
}

func TestUnresolvedSecretsWhitelistNothing(t *testing.T) {
	cfg := MustParse("secrets:\n  - env: BOX_TEST_LIVE\n    source: live-value\n    hosts:\n      live.example.com: {allow: true}\n" +
		"  - env: BOX_TEST_ABSENT_THAT_MUST_NOT_EXIST\n    source: $BOX_TEST_ABSENT_THAT_MUST_NOT_EXIST\n    optional: true\n    hosts:\n      absent.example.com: {allow: true}\n")
	resolved, err := ResolveSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resolved.Skipped, []string{"BOX_TEST_ABSENT_THAT_MUST_NOT_EXIST"}) {
		t.Fatal(resolved.Skipped)
	}
	allow := EffectiveAllowHosts(cfg, resolved)
	if !contains(allow, "live.example.com") || contains(allow, "absent.example.com") {
		t.Fatal(allow)
	}
}

func TestOptionalPassthroughSecretsSkipWhenAbsent(t *testing.T) {
	cfg := MustParse("secrets:\n  - env: BOX_TEST_OPTIONAL_THAT_MUST_NOT_EXIST\n    source: $BOX_TEST_OPTIONAL_THAT_MUST_NOT_EXIST\n    optional: true\n    hosts:\n      example.com: {allow: true}\n")
	resolved, _ := ResolveSecrets(cfg)
	if len(resolved.Found) != 0 || len(resolved.Skipped) != 1 {
		t.Fatalf("%+v", resolved)
	}
}

func TestRequiredSecretsStillAbortWhenAbsent(t *testing.T) {
	cfg := MustParse("secrets:\n  - env: BOX_TEST_REQUIRED_THAT_MUST_NOT_EXIST\n    source: $BOX_TEST_REQUIRED_THAT_MUST_NOT_EXIST\n    hosts:\n      example.com: {allow: true}\n")
	_, err := ResolveSecrets(cfg)
	if err == nil || !strings.Contains(err.Error(), "BOX_TEST_REQUIRED_THAT_MUST_NOT_EXIST") {
		t.Fatal(err)
	}
}

func TestInitWritesAParseableWorkspaceOverlayOnce(t *testing.T) {
	workspace := testDir(t, "ws")
	path, err := InitWorkspace(workspace)
	if err != nil || path != filepath.Join(workspace, LocalOverlayFile) {
		t.Fatal(path, err)
	}
	cfg, err := MergeConfigs([]string{read(t, path)})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := InitWorkspace(workspace); err == nil {
		t.Fatal("second init must refuse to overwrite")
	}
}

func TestAllowAppendsItemsCommentsAndSections(t *testing.T) {
	dir := testDir(t, "allow")
	path := filepath.Join(dir, "a.yml")
	write(t, path, "network:\n  # note\n  allow:\n    - a.example.com\n  deny: []\n")
	if outcome, err := AllowHostInFile(path, "b.example.com"); err != nil || outcome != Added {
		t.Fatal(outcome, err)
	}
	text := read(t, path)
	if !strings.Contains(text, "# note") || !strings.Contains(text, "    - a.example.com\n    - b.example.com\n") {
		t.Fatal(text)
	}
	merged, err := MergeConfigs([]string{text})
	if err != nil || Validate(merged) != nil {
		t.Fatal(err)
	}
	if outcome, _ := AllowHostInFile(path, "b.example.com"); outcome != AlreadyPresent {
		t.Fatal("duplicate must report presence")
	}

	bare := filepath.Join(dir, "b.yml")
	write(t, bare, "network:\n  allow_everything: false\n")
	AllowHostInFile(bare, ".example.com")
	if !strings.Contains(read(t, bare), "network:\n  allow:\n    - .example.com\n") {
		t.Fatal(read(t, bare))
	}

	empty := filepath.Join(dir, "c.yml")
	write(t, empty, "# just a comment\n")
	AllowHostInFile(empty, "example.com")
	text = read(t, empty)
	if !strings.Contains(text, "# just a comment") || !strings.Contains(text, "network:\n  allow:\n    - example.com\n") {
		t.Fatal(text)
	}

	inline := filepath.Join(dir, "d.yml")
	write(t, inline, "network:\n  allow: []\n")
	AllowHostInFile(inline, "example.com")
	if !strings.Contains(read(t, inline), "  allow:\n    - example.com\n") {
		t.Fatal(read(t, inline))
	}

	for _, bad := range []string{"", "has space.com", "https://example.com/x", "a/b"} {
		if _, err := AllowHostInFile(path, bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestNetworkAllowAndDenyMergeAdditively(t *testing.T) {
	cfg, err := MergeConfigs([]string{
		"network:\n  allow: [example.com]\n  deny: [blocked.example.com]\n",
		"network:\n  allow: [example.com, other.example.com]\n  deny: [evil.example.com]\n",
	})
	if err != nil || Validate(cfg) != nil {
		t.Fatal(err)
	}
	count := 0
	for _, host := range cfg.Network.Allow {
		if host == "example.com" {
			count++
		}
	}
	if !contains(cfg.Network.Allow, "mise.run") || !contains(cfg.Network.Allow, "other.example.com") || count != 1 {
		t.Fatal(cfg.Network.Allow)
	}
	if !contains(cfg.Network.Deny, "blocked.example.com") || !contains(cfg.Network.Deny, "evil.example.com") {
		t.Fatal(cfg.Network.Deny)
	}
}

func TestOtherListsStillReplace(t *testing.T) {
	cfg, err := MergeConfigs([]string{"network:\n  ports: [6080]\n", "network:\n  ports: [5900]\n"})
	if err != nil || len(cfg.Network.Ports) != 1 || cfg.Network.Ports[0].Host != 5900 {
		t.Fatal(cfg.Network.Ports, err)
	}
}

func TestHostRuleDefaultsToAllow(t *testing.T) {
	cfg := MustParse("secrets:\n  - env: X\n    source: lit\n    hosts:\n      a.com: {}\n      b.com: {allow: false}\n")
	if got := cfg.Secrets[0].AllowedHosts(); fmt.Sprint(got) != "[a.com]" {
		t.Fatal(got)
	}
}
