// Package resources embeds box's shipped defaults and documentation.
package resources

import _ "embed"

// DefaultYAML is the strict schema contract and embedded default config.
//
//go:embed default.yml
var DefaultYAML string

// Skill is the agent skill printed by `box --skill`.
//
//go:embed skill.md
var Skill string
