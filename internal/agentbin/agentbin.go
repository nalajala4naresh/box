// Package agentbin embeds the guest agent, cross-compiled by `make` into
// bin/box-agent-linux-<arch>.
package agentbin

import (
	"embed"
	"fmt"
	"runtime"
)

//go:generate sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=$(go env GOARCH) go build -trimpath -ldflags='-s -w' -o bin/box-agent-linux-$(go env GOARCH) ../../cmd/box-agent"

//go:embed all:bin
var files embed.FS

// Binary returns the guest agent for the host architecture; the guest
// always matches it (HVF and KVM run native guests only).
func Binary() ([]byte, error) {
	name := "bin/box-agent-linux-" + runtime.GOARCH
	data, err := files.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("guest agent %s is not embedded in this binary; build box with `make`", name)
	}
	return data, nil
}
