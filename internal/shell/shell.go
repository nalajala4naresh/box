// Package shell holds the POSIX quoting helpers every generated guest script
// goes through.
package shell

import "strings"

// Quote returns arg as a single POSIX shell word. Plain words pass through
// untouched; anything else is single-quoted.
func Quote(arg string) string {
	if arg == "" {
		return "''"
	}
	plain := true
	for _, c := range arg {
		if !(c < 0x80 && (isAlnum(byte(c)) || strings.ContainsRune("-_./:=", c))) {
			plain = false
			break
		}
	}
	if plain {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}

// Join quotes every argument and joins them with spaces.
func Join(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = Quote(arg)
	}
	return strings.Join(quoted, " ")
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
