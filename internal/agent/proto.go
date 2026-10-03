// Package agent is the wire protocol between the host and wrap-agent, the
// guest-side process libkrun runs as the VM workload.
//
// Every operation is one connection over the vsock port libkrun maps to a
// host unix socket. The host sends a JSON request frame first; both sides
// then exchange typed frames until the guest sends an exit frame.
package agent

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// VsockPort is the guest vsock port wrap-agent listens on.
const VsockPort = 10700

// Version is bumped whenever the protocol changes incompatibly.
const Version = 1

// BootPath is where the host writes the boot configuration inside the
// rootfs before starting the VM.
const BootPath = "/.wrap/boot.json"

// AgentPath is where the host installs the agent binary inside the rootfs.
const AgentPath = "/.wrap/wrap-agent"

// Frame types.
const (
	// Host → guest.
	FrameRequest    byte = 'J'
	FrameStdin      byte = 'I'
	FrameStdinClose byte = 'C'
	FrameResize     byte = 'R'
	FrameSignal     byte = 'S'

	// Guest → host.
	FrameStdout byte = 'O'
	FrameStderr byte = 'E'
	FrameExit   byte = 'X'
	FrameFailed byte = 'F'
)

// MaxFrame bounds a single frame payload.
const MaxFrame = 4 << 20

// Request is the first frame of every connection.
type Request struct {
	Op string `json:"op"` // ping, exec, write, mkdir, exists, shutdown

	// exec
	Argv      []string `json:"argv,omitempty"`
	Env       []string `json:"env,omitempty"`
	Cwd       string   `json:"cwd,omitempty"`
	User      string   `json:"user,omitempty"`
	TTY       bool     `json:"tty,omitempty"`
	Rows      uint16   `json:"rows,omitempty"`
	Cols      uint16   `json:"cols,omitempty"`
	TimeoutMS int64    `json:"timeout_ms,omitempty"`

	// write, mkdir, exists
	Path string `json:"path,omitempty"`
	Mode uint32 `json:"mode,omitempty"`
	// Owner is the guest account that ends up owning created paths. Empty
	// keeps root.
	Owner string `json:"owner,omitempty"`
}

// Resize is the payload of a FrameResize.
type Resize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// Exit is the payload of a FrameExit.
type Exit struct {
	Code    int    `json:"code"`
	Version int    `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

// Boot is the guest configuration the agent applies before serving.
type Boot struct {
	Hostname string  `json:"hostname"`
	Mounts   []Mount `json:"mounts,omitempty"`
	Net      *Net    `json:"net,omitempty"`
	// Timezone is an IANA name like America/Los_Angeles.
	Timezone string `json:"timezone,omitempty"`
	// CAPath is a guest path to a PEM CA certificate to trust.
	CAPath string `json:"ca_path,omitempty"`
}

// Mount is one virtio-fs share.
type Mount struct {
	Tag      string `json:"tag"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// Net is the static IPv4 configuration of eth0.
type Net struct {
	Iface   string `json:"iface"`
	Address string `json:"address"` // CIDR
	Gateway string `json:"gateway"`
	DNS     string `json:"dns"`
	MTU     int    `json:"mtu"`
}

// Conn serializes frame writes from several goroutines.
type Conn struct {
	rw io.ReadWriter
	mu sync.Mutex
}

func NewConn(rw io.ReadWriter) *Conn { return &Conn{rw: rw} }

// Write sends one frame.
func (c *Conn) Write(typ byte, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("frame too large: %d bytes", len(payload))
	}
	var header [5]byte
	header[0] = typ
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.rw.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := c.rw.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON sends one frame with a JSON payload.
func (c *Conn) WriteJSON(typ byte, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Write(typ, payload)
}

// WriteStream sends r as a sequence of typ frames, without a close frame.
func (c *Conn) WriteStream(typ byte, r io.Reader) error {
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := c.Write(typ, buf[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Read receives one frame. It is not safe for concurrent use.
func (c *Conn) Read() (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(c.rw, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size > MaxFrame {
		return 0, nil, fmt.Errorf("frame too large: %d bytes", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(c.rw, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}
