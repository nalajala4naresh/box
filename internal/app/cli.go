package app

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SubKind names a box subcommand.
type SubKind int

const (
	SubNone SubKind = iota
	SubInit
	SubAllow
	SubConfig
	SubLog
)

// CLI is the parsed command line.
type CLI struct {
	Rebuild bool
	Reset   bool
	// Target is the host workspace whose box to target (-c/--cwd).
	Target string
	Skill  bool
	CPUs   *uint8
	// MemoryBoot overrides initial guest memory in MiB.
	MemoryBoot *uint32
	// Memory overrides the memory ceiling in MiB.
	Memory                 *uint32
	Config                 string
	NetworkAllowEverything bool

	Sub SubKind
	// Allow subcommand.
	AllowHost   string
	AllowGlobal bool
	// Log subcommand.
	LogTail   int
	LogFollow bool

	// Command runs inside the VM. Default: login zsh.
	Command []string
	// Separator records an explicit `--` before the guest command.
	Separator bool
}

// ErrHelp is returned after help text was printed.
var ErrHelp = errors.New("help requested")

const mainHelp = `Enter a cached microVM from a layered snapshot

Usage: box [OPTIONS] [COMMAND]...
       box [OPTIONS] <SUBCOMMAND>

Subcommands:
  init    Write a workspace-local ` + "`BOXFILE`" + ` and exit without booting a VM
  allow   Allow a host through egress and exit without booting a VM
  config  Print the fully merged config as YAML and exit without booting a VM
  log     Show requests the sandbox denied, newest last, without booting a VM

Arguments:
  [COMMAND]...  Command to run inside the VM. Default: login zsh

Options:
      --rebuild                   Rebuild every cached layer snapshot from scratch
      --reset                     Recreate this directory's sandbox from the latest base snapshot
  -c, --cwd <TARGET>              Host workspace whose box to target
      --skill                     Print the box agent skill and exit
      --cpus <CPUS>               Override the configured vCPU count for the session VM
      --memory-boot <MEMORY_BOOT> Override initial guest memory in MiB
      --memory <MEMORY>           Override the configured memory ceiling in MiB
      --config <CONFIG>           Explicit config overlay (also $BOX_CONFIG)
      --network-allow-everything  Open all egress for this entry only [aliases: --yolo]
  -h, --help                      Print help
`

const allowHelp = `Allow a host through egress and exit without booting a VM. Writes the local
` + "`BOXFILE`" + `, or the global config with ` + "`--global`" + `. Takes effect on next entry (the
session recreates automatically).

Usage: box allow [OPTIONS] <HOST>

Arguments:
  <HOST>  Host to allow: exact, ` + "`.suffix`" + `, or ` + "`*.wildcard`" + `

Options:
  -g, --global  Write ` + "`~/.config/box/config.yml`" + ` instead of the workspace file
  -h, --help    Print help
`

const logHelp = `Show requests the sandbox denied, newest last, without booting a VM. Reads this
workspace's session logs. (Use ` + "`box -- log`" + ` to run ` + "`log`" + ` inside the guest.)

Usage: box log [OPTIONS]

Options:
      --tail <TAIL>  Show only the last N denied requests [default: 50]
  -f, --follow       Keep printing new denied requests as they arrive
  -h, --help         Print help
`

const initHelp = `Write a workspace-local ` + "`BOXFILE`" + ` and exit without booting a VM. (Use
` + "`box -- init`" + ` to run ` + "`init`" + ` inside the guest.)

Usage: box init
`

const configHelp = `Print the fully merged config as YAML and exit without booting a VM. Includes
every overlay (` + "`config.yml`, `config.d`, `BOXFILE`, `--config PATH` / `$BOX_CONFIG`" + `).
Secret sources stay as written; resolved values never appear. (Use
` + "`box -- config`" + ` to run ` + "`config`" + ` inside the guest.)

Usage: box config
`

// ParseCLI parses box's arguments (without the program name). Help text
// goes to out.
func ParseCLI(args []string, out func(string)) (CLI, error) {
	cli := CLI{LogTail: 50}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			cli.Separator = true
			cli.Command = append([]string{}, args[i+1:]...)
			return cli, nil
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			switch arg {
			case "init", "allow", "config", "log":
				return parseSub(cli, arg, args[i+1:], out)
			case "help":
				out(mainHelp)
				return cli, ErrHelp
			}
			cli.Command = append([]string{}, args[i:]...)
			return cli, nil
		}
		name, value, hasValue := strings.Cut(arg, "=")
		take := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("a value is required for '%s <VALUE>' but none was supplied", name)
			}
			i++
			return args[i], nil
		}
		noValue := func() error {
			if hasValue {
				return fmt.Errorf("unexpected value '%s' for '%s' found; no more were expected", value, name)
			}
			return nil
		}
		var err error
		switch {
		case name == "-h" || name == "--help":
			out(mainHelp)
			return cli, ErrHelp
		case name == "--rebuild":
			cli.Rebuild, err = true, noValue()
		case name == "--reset":
			cli.Reset, err = true, noValue()
		case name == "--skill":
			cli.Skill, err = true, noValue()
		case name == "--network-allow-everything" || name == "--yolo":
			cli.NetworkAllowEverything, err = true, noValue()
		case name == "-c" || name == "--cwd":
			cli.Target, err = take()
		case strings.HasPrefix(arg, "-c") && len(arg) > 2 && !strings.HasPrefix(arg, "--"):
			cli.Target = arg[2:]
		case name == "--config":
			cli.Config, err = take()
		case name == "--cpus":
			var v string
			if v, err = take(); err == nil {
				var n uint64
				if n, err = strconv.ParseUint(v, 10, 8); err != nil {
					err = fmt.Errorf("invalid value '%s' for '--cpus <CPUS>': %v", v, err)
				} else {
					c := uint8(n)
					cli.CPUs = &c
				}
			}
		case name == "--memory" || name == "--memory-boot":
			var v string
			if v, err = take(); err == nil {
				var n uint64
				if n, err = strconv.ParseUint(v, 10, 32); err != nil {
					err = fmt.Errorf("invalid value '%s' for '%s': %v", v, name, err)
				} else {
					m := uint32(n)
					if name == "--memory" {
						cli.Memory = &m
					} else {
						cli.MemoryBoot = &m
					}
				}
			}
		default:
			return cli, fmt.Errorf("unexpected argument '%s' found\n\n  tip: to pass '%s' as a value, use '-- %s'", arg, arg, arg)
		}
		if err != nil {
			return cli, err
		}
	}
	return cli, nil
}

func parseSub(cli CLI, name string, args []string, out func(string)) (CLI, error) {
	switch name {
	case "init", "config":
		help := initHelp
		cli.Sub = SubInit
		if name == "config" {
			help, cli.Sub = configHelp, SubConfig
		}
		for _, arg := range args {
			if arg == "-h" || arg == "--help" {
				out(help)
				return cli, ErrHelp
			}
			return cli, fmt.Errorf("unexpected argument '%s' found", arg)
		}
	case "allow":
		cli.Sub = SubAllow
		for _, arg := range args {
			switch {
			case arg == "-h" || arg == "--help":
				out(allowHelp)
				return cli, ErrHelp
			case arg == "-g" || arg == "--global":
				cli.AllowGlobal = true
			case strings.HasPrefix(arg, "-") && len(arg) > 1 && cli.AllowHost == "":
				// A leading-dot host is not a flag; a dash one is.
				return cli, fmt.Errorf("unexpected argument '%s' found", arg)
			case cli.AllowHost == "":
				cli.AllowHost = arg
			default:
				return cli, fmt.Errorf("unexpected argument '%s' found", arg)
			}
		}
		if cli.AllowHost == "" {
			return cli, errors.New("the following required arguments were not provided:\n  <HOST>\n\nUsage: box allow [OPTIONS] <HOST>")
		}
	case "log":
		cli.Sub = SubLog
		for i := 0; i < len(args); i++ {
			arg := args[i]
			key, value, hasValue := strings.Cut(arg, "=")
			switch {
			case arg == "-h" || arg == "--help":
				out(logHelp)
				return cli, ErrHelp
			case arg == "-f" || arg == "--follow":
				cli.LogFollow = true
			case key == "--tail":
				if !hasValue {
					if i+1 >= len(args) {
						return cli, errors.New("a value is required for '--tail <TAIL>' but none was supplied")
					}
					i++
					value = args[i]
				}
				n, err := strconv.Atoi(value)
				if err != nil || n < 0 {
					return cli, fmt.Errorf("invalid value '%s' for '--tail <TAIL>'", value)
				}
				cli.LogTail = n
			default:
				return cli, fmt.Errorf("unexpected argument '%s' found", arg)
			}
		}
	}
	return cli, nil
}
