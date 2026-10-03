// Package resources embeds wrap's shipped defaults and documentation.
package resources

import _ "embed"

// DefaultYAML is the strict schema contract and embedded default config.
//
//go:embed default.yml
var DefaultYAML string

// Skill is the agent skill printed by `wrap --skill`.
//
//go:embed skill.md
var Skill string
