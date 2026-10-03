package app

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/nalajala4naresh/box/internal/config"
	"github.com/nalajala4naresh/box/internal/netstack"
	"github.com/nalajala4naresh/box/resources"
)

func parse(t *testing.T, args ...string) CLI {
	t.Helper()
	cli, err := ParseCLI(args, func(string) {})
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return cli
}

func TestLookupNameExtraction(t *testing.T) {
	body := "DEBUG hickory_net::xfer: enqueueing message:QUERY:" +
		"[Query { name: Name(\"Example.COM.\"), query_type: A, query_class: IN }]\n" +
		";; Example.COM. IN A\n" +
		";; other.net. IN AAAA"
	if got := strings.Join(dnsLookupNames(body), ","); got != "example.com,other.net" {
		t.Fatal(got)
	}
	for _, none := range []string{"INFO sandbox starting", ";; not a question", "Name(\"unterminated"} {
		if got := dnsLookupNames(none); len(got) != 0 {
			t.Fatalf("%q: %v", none, got)
		}
	}
	// The network's own query lines.
	if got := dnsLookupNames(`DEBUG dns query name: Name("api.github.com.") type=A`); len(got) != 1 || got[0] != "api.github.com" {
		t.Fatal(got)
	}
}

func TestDenialLineMatching(t *testing.T) {
	for _, line := range []string{
		"DNS query denied by network policy",
		"TCP egress denied by domain policy",
		"TLS egress denied by domain policy",
		"TLS SNI did not match CONNECT authority",
		"level=DEBUG msg=\"DNS query denied by network policy\" domain=example.com",
	} {
		if !isDenialLine(line) {
			t.Fatalf("%q must match", line)
		}
	}
	for _, line := range []string{"TLS bypass", "sandbox started", "", "TCP egress refused (default deny)"} {
		if isDenialLine(line) {
			t.Fatalf("%q must not match", line)
		}
	}
}

func TestNamesSandboxFromRealpath(t *testing.T) {
	a := sandboxNameFromReal("/home/tobi/src/app")
	if a != sandboxNameFromReal("/home/tobi/src/app") || a == sandboxNameFromReal("/home/tobi/src/other") {
		t.Fatal("names must be stable and distinct")
	}
	if !strings.HasPrefix(a, "box-") || len(a) != len("box-")+16 {
		t.Fatal(a)
	}
}

func TestSessionPolicyCoversFoldedSecretHosts(t *testing.T) {
	cfg := config.MustParse("network:\n  allow: [example.com]\n  deny: [blocked.example.com]\n" +
		"secrets:\n  - env: TEST_TOKEN\n    source: literal\n    hosts:\n      api.example.com: {allow: true}\n      blocked.example.com: {allow: true}\n" +
		"  - env: BOX_TEST_ABSENT_THAT_MUST_NOT_EXIST\n    source: $BOX_TEST_ABSENT_THAT_MUST_NOT_EXIST\n    optional: true\n    hosts:\n      absent.example.com: {allow: true}\n")
	secrets, err := config.ResolveSecrets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	policy := sessionPolicy(cfg, secrets)
	if !policy.Reachable("api.example.com") || policy.Reachable("blocked.example.com") || policy.Reachable("absent.example.com") {
		t.Fatalf("%+v", policy)
	}
}

func TestDenyOverridesAllowForCoveredSubdomain(t *testing.T) {
	cfg := config.MustParse("network:\n  allow: [.github.com]\n  deny: [gist.github.com]\n")
	secrets, _ := config.ResolveSecrets(cfg)
	policy := sessionPolicy(cfg, secrets)
	if !policy.Reachable("api.github.com") || policy.Reachable("gist.github.com") {
		t.Fatal("deny must evaluate before allow")
	}
}

func resolved(env string, headers map[string]string, hosts ...string) config.ResolvedSecrets {
	return config.ResolvedSecrets{Found: []config.ResolvedSecret{{Env: env, Value: "value", Headers: headers, Hosts: hosts}}}
}

func TestGithubAuthSnippetPrefersGhThenAliases(t *testing.T) {
	snippet := MiseGithubAuthSnippet()
	if strings.Index(snippet, "gh auth token") > strings.Index(snippet, `"$GH_TOKEN"`) {
		t.Fatal("gh must be tried first")
	}
	if !strings.Contains(snippet, config.SecretPlaceholder) || !strings.Contains(snippet, `if [ -z "${GITHUB_TOKEN:-}" ]`) {
		t.Fatal(snippet)
	}
	if !strings.Contains(BuildScript("true"), snippet) || !strings.Contains(guestExports(config.MustParse(resources.DefaultYAML)), snippet) {
		t.Fatal("both build stages and session shells run it")
	}
}

func snippetGithubToken(t *testing.T, ghToken, githubToken *string) string {
	t.Helper()
	cmd := exec.Command("sh", "-c", MiseGithubAuthSnippet()+`printf '%s' "${GITHUB_TOKEN:-unset}"`)
	cmd.Env = []string{"PATH=/nonexistent"}
	if ghToken != nil {
		cmd.Env = append(cmd.Env, "GH_TOKEN="+*ghToken)
	}
	if githubToken != nil {
		cmd.Env = append(cmd.Env, "GITHUB_TOKEN="+*githubToken)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func ptr(s string) *string { return &s }

func TestGithubAuthSnippetBehavior(t *testing.T) {
	if got := snippetGithubToken(t, ptr(config.SecretPlaceholder), nil); got != config.SecretPlaceholder {
		t.Fatal(got)
	}
	if got := snippetGithubToken(t, ptr("live-value"), ptr("preset")); got != "preset" {
		t.Fatal(got)
	}
	if got := snippetGithubToken(t, nil, nil); got != "unset" {
		t.Fatal(got)
	}
	// A clean environment, like Rust's env_clear(): the host's gh (and its
	// real token) must never be reachable from this test.
	cmd := exec.Command("sh", "-c", "set -eu\n"+MiseGithubAuthSnippet()+`printf '%s' "${GITHUB_TOKEN:-unset}"`)
	cmd.Env = []string{"PATH=/nonexistent"}
	out, err := cmd.Output()
	if err != nil || string(out) != "unset" {
		t.Fatalf("must survive set -eu: got %d bytes, err %v", len(out), err)
	}
}

func TestGitExtraheaderComesFromDeclaredAuthorization(t *testing.T) {
	live := resolved("GH_TOKEN", map[string]string{"Authorization": "Bearer $GH_TOKEN"}, "github.com")
	if !secretsNeedGitHeader(nil, live) || secretsNeedGitHeader([]string{"true"}, live) {
		t.Fatal("needs header")
	}
	if name, value, ok := githubExtraheader(live); !ok || name != "Authorization" || value != "Bearer $GH_TOKEN" {
		t.Fatal(name, value)
	}
	for _, none := range []config.ResolvedSecrets{
		{},
		resolved("GH_TOKEN", nil, "github.com"),
		resolved("OTHER", map[string]string{"Authorization": "Bearer $OTHER"}, "api.example.com"),
	} {
		if secretsNeedGitHeader(nil, none) {
			t.Fatalf("%+v", none)
		}
	}
	lower := resolved("GH_TOKEN", map[string]string{"authorization": "Bearer $GH_TOKEN"}, "github.com")
	if name, _, _ := githubExtraheader(lower); name != "authorization" {
		t.Fatal(name)
	}
}

func TestDerivesIntendedBuildStages(t *testing.T) {
	cfg := config.MustParse("agents:\n  - name: pi\n    package: mise:pi@latest\nlayers:\n  - id: dotfiles\n    script: echo custom\n")
	stages, err := BuildStages(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i, stage := range stages {
		ids = append(ids, stage.ID)
		if !strings.HasPrefix(stage.Snapshot, baseSnapshotPrefix+"-0"+string(rune('1'+i))+"-"+stage.ID+"-") {
			t.Fatal(stage.Snapshot)
		}
		if err := exec.Command("/bin/bash", "-n", "-c", stage.Script).Run(); err != nil {
			t.Fatalf("invalid generated script for %s", stage.ID)
		}
	}
	if strings.Join(ids, ",") != "image,agents,dotfiles" {
		t.Fatal(ids)
	}
	if strings.Contains(stages[0].Script, "pacman") || stages[0].Script != BuildScript("true") ||
		!strings.Contains(stages[0].Script, "export HOME=/home/user") ||
		!strings.Contains(stages[0].Script, "export MISE_DATA_DIR=/opt/mise/data") ||
		!strings.Contains(stages[0].Script, "/opt/mise/data/shims") ||
		strings.Contains(stages[0].Script, "/root") ||
		!strings.HasSuffix(strings.TrimRight(stages[0].Script, "\n"), "\ntrue") {
		t.Fatal(stages[0].Script)
	}
	if strings.Count(stages[1].Script, "mise use --global --pin") != 1 || !strings.Contains(stages[1].Script, "pi@latest") {
		t.Fatal(stages[1].Script)
	}
	if !strings.Contains(stages[2].Script, "echo custom") {
		t.Fatal(stages[2].Script)
	}
	changed, _ := BuildStages(config.MustParse("agents:\n  - name: pi\n    package: mise:pi@latest\nlayers:\n  - id: dotfiles\n    script: echo changed\n"))
	if stages[0].Snapshot != changed[0].Snapshot || stages[1].Snapshot != changed[1].Snapshot || stages[2].Snapshot == changed[2].Snapshot {
		t.Fatal("only the changed layer and its descendants rebuild")
	}
}

func TestImageStageIsFinalWithoutCustomization(t *testing.T) {
	stages, _ := BuildStages(config.MustParse("{}"))
	if len(stages) != 1 || !strings.HasPrefix(stages[0].Snapshot, "box-image-01-image-") {
		t.Fatal(stages)
	}
}

func TestResolvesTryPackageThroughItsGemAlias(t *testing.T) {
	if got, _ := miseInstallPackage("github:tobi/try@latest"); got != "gem:try-cli@latest" {
		t.Fatal(got)
	}
}

func TestRejectsPackageOptions(t *testing.T) {
	if _, err := BuildStages(config.MustParse("agents: [{name: pi, package: 'mise:--root'}]\n")); err == nil {
		t.Fatal("option-looking package must fail")
	}
}

func TestCLIParsing(t *testing.T) {
	if !parse(t, "--network-allow-everything", "--", "/bin/true").NetworkAllowEverything ||
		!parse(t, "--yolo", "--", "/bin/true").NetworkAllowEverything ||
		parse(t, "--", "/bin/true").NetworkAllowEverything {
		t.Fatal("allow-everything flag")
	}
	cli := parse(t, "allow", "example.com")
	if cli.Sub != SubAllow || cli.AllowHost != "example.com" || cli.AllowGlobal {
		t.Fatalf("%+v", cli)
	}
	cli = parse(t, "-c", "dir", "allow", "-g", ".example.com")
	if cli.Sub != SubAllow || cli.AllowHost != ".example.com" || !cli.AllowGlobal || cli.Target != "dir" {
		t.Fatalf("%+v", cli)
	}
	if _, err := ParseCLI([]string{"allow"}, func(string) {}); err == nil {
		t.Fatal("allow needs a host")
	}
	if cli := parse(t, "init"); cli.Sub != SubInit || len(cli.Command) != 0 {
		t.Fatalf("%+v", cli)
	}
	if cli := parse(t, "--", "init"); cli.Sub != SubNone || strings.Join(cli.Command, " ") != "init" || !cli.Separator {
		t.Fatalf("%+v", cli)
	}
	if cli := parse(t, "--config", "extra.yml", "config"); cli.Sub != SubConfig || cli.Config != "extra.yml" {
		t.Fatalf("%+v", cli)
	}
	if cli := parse(t, "--", "config"); cli.Sub != SubNone || cli.Command[0] != "config" {
		t.Fatalf("%+v", cli)
	}
	if cli := parse(t, "--cpus", "8", "git", "log", "--oneline"); *cli.CPUs != 8 || strings.Join(cli.Command, " ") != "git log --oneline" || cli.Separator {
		t.Fatalf("%+v", cli)
	}
	if cli := parse(t, "log", "--tail", "5", "-f"); cli.Sub != SubLog || cli.LogTail != 5 || !cli.LogFollow {
		t.Fatalf("%+v", cli)
	}
	if cli := parse(t, "--memory=8192", "--memory-boot", "4096"); *cli.Memory != 8192 || *cli.MemoryBoot != 4096 {
		t.Fatalf("%+v", cli)
	}
	if _, err := ParseCLI([]string{"--bogus"}, func(string) {}); err == nil {
		t.Fatal("unknown flag")
	}
}

func TestLifecycleFlagsBypassFastMethods(t *testing.T) {
	command := []string{"bash", "true"}
	if _, ok := fastMethod(false, false, command); !ok {
		t.Fatal("method")
	}
	if _, ok := fastMethod(true, false, command); ok {
		t.Fatal("rebuild")
	}
	if _, ok := fastMethod(false, true, command); ok {
		t.Fatal("reset")
	}
}

func TestGuestExports(t *testing.T) {
	cfg := config.MustParse(resources.DefaultYAML)
	cfg.Env["SSH_CONNECTION"] = "true"
	exports := guestExports(cfg)
	if !strings.Contains(exports, "SSH_CONNECTION=true") || !strings.Contains(exports, "/opt/mise/data/shims") ||
		!strings.Contains(exports, "$HOME/.local/bin") || strings.Contains(exports, "/root") {
		t.Fatal(exports)
	}
}

func TestGuestPathExportsAreIdempotent(t *testing.T) {
	run := func(path string) string {
		cmd := exec.Command("sh", "-c", GuestPathExports()+`; printf '%s' "$PATH"`)
		cmd.Env = []string{"HOME=/home/user", "PATH=" + path}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	once := run("/usr/bin:/bin")
	if once != "/usr/local/bin:/home/user/.local/bin:/opt/mise/data/shims:/opt/box/bin:/usr/bin:/bin" {
		t.Fatal(once)
	}
	if run(once) != once {
		t.Fatal("second application must not stack")
	}
}

func TestSessionDigestTracksSessionConfig(t *testing.T) {
	cfg := config.MustParse("network:\n  allow: [example.com]\n" +
		"secrets:\n  - env: TEST_TOKEN\n    source: literal\n    headers:\n      X-Api-Token: $TEST_TOKEN\n    hosts:\n      api.example.com: {allow: true}\n" +
		"agents:\n  - name: pi\n    package: mise:pi@latest\n    host-copy: ~/.pi\n")
	secrets, _ := config.ResolveSecrets(cfg)
	base := sessionConfigDigest(cfg, secrets)
	if base != sessionConfigDigest(cfg, secrets) {
		t.Fatal("deterministic")
	}
	changed := config.MustParse("network:\n  allow: [example.com, other.example.com]\n")
	changed.Secrets, changed.Agents = cfg.Secrets, cfg.Agents
	changedSecrets, _ := config.ResolveSecrets(changed)
	if base == sessionConfigDigest(changed, changedSecrets) {
		t.Fatal("network drift must change it")
	}
	rotated := config.ResolvedSecrets{Found: append([]config.ResolvedSecret(nil), secrets.Found...)}
	rotated.Found[0].Value = "rotated"
	if base != sessionConfigDigest(cfg, rotated) {
		t.Fatal("rotated values leave the structural digest alone")
	}
	values := secretValuesDigest(rotated)
	if values == secretValuesDigest(secrets) || strings.Contains(values, "rotated") {
		t.Fatal("values digest")
	}
	if base == sessionConfigDigest(cfg, config.ResolvedSecrets{Found: secrets.Found, Skipped: []string{"EXTRA"}}) {
		t.Fatal("a newly skipped optional must change it")
	}
	open := cfg
	open.Network.AllowEverything = true
	if base == sessionConfigDigest(open, secrets) {
		t.Fatal("allow-everything override must change it")
	}
}

func TestIPv6DisableScriptTargetsProcSys(t *testing.T) {
	script := ipv6DisableScript()
	if !strings.Contains(script, "/proc/sys/net/ipv6/conf/all/disable_ipv6") || !strings.Contains(script, "/proc/sys/net/ipv6/conf/default/disable_ipv6") {
		t.Fatal(script)
	}
	if err := exec.Command("/bin/sh", "-n", "-c", script).Run(); err != nil {
		t.Fatal(err)
	}
}

func TestDropsToUserUnlessWorkspaceIsRootOwned(t *testing.T) {
	user, root := hostIdentityT{1000, 1000}, hostIdentityT{0, 0}
	if guestUserFor(user) != GuestUser || guestHomeFor(user) != GuestHome || guestUserFor(root) != "root" || guestHomeFor(root) != "/root" {
		t.Fatal("identity mapping")
	}
}

func TestChownsImportedStateAndHomeParents(t *testing.T) {
	script := chownToGuestUser("/home/user/.config/pi/agent")
	if !strings.HasPrefix(script, "chown -R user:user /home/user/.config/pi/agent\n") ||
		!strings.Contains(script, "chown user:user /home/user/.config/pi\n") ||
		!strings.Contains(script, "chown user:user /home/user/.config\n") ||
		strings.Contains(script, "chown user:user /home/user\n") || strings.Contains(script, "chown user:user /\n") {
		t.Fatal(script)
	}
	if got := chownToGuestUser("/opt/state"); got != "chown -R user:user /opt/state\n" {
		t.Fatal(got)
	}
}

func TestBalloonsMemoryAboveSessionMinimum(t *testing.T) {
	cases := [][4]uint32{{1024, 4096, 4096, 4096}, {8192, 4096, 4096, 4096}, {0, 0, 4096, 4096}, {4096, 8192, 4096, 8192}}
	for _, c := range cases {
		if boot, max := balloonMemory(c[0], c[1]); boot != c[2] || max != c[3] {
			t.Fatalf("%v: %d %d", c, boot, max)
		}
	}
}

func TestAlignScriptParsesAndSkipsTheShare(t *testing.T) {
	script := alignScript(hostIdentityT{uid: 501, gid: 20})
	if err := exec.Command("/bin/sh", "-n", "-c", script).Run(); err != nil {
		t.Fatalf("%v\n%s", err, script)
	}
	if !strings.Contains(script, "uid=501; gid=20") || !strings.Contains(script, "-xdev") || strings.Contains(script, "chown -R") {
		t.Fatal(script)
	}
}

func TestExposureReportUsesEffectivePolicy(t *testing.T) {
	cfg := config.MustParse("network:\n  allow: [mise.run]\n  ports: [6080, '5901:5900']\nsecrets: []\n")
	report := exposureReport(cfg, config.ResolvedSecrets{}, nil, []config.Source{{}})
	if strings.Join(report.Ports, ",") != "6080,5901:5900" || report.Sources[0] != "embedded defaults" {
		t.Fatalf("%+v", report)
	}
	var _ netstack.Policy = sessionPolicy(cfg, config.ResolvedSecrets{})
}
