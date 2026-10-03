package netstack

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Logger appends timestamped diagnostic lines to a session's system log.
// `box log` reads them back. Lines never contain secret values.
type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

// OpenLogger appends to path, creating it.
func OpenLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{out: f}, nil
}

// NewLogger writes to w.
func NewLogger(w io.Writer) *Logger { return &Logger{out: w} }

// Printf writes one line: `<RFC3339 UTC> <LEVEL> <message>`.
func (l *Logger) Printf(level, format string, args ...any) {
	if l == nil || l.out == nil {
		return
	}
	line := fmt.Sprintf("%s %s %s\n", time.Now().UTC().Format("2006-01-02T15:04:05Z"), level, fmt.Sprintf(format, args...))
	l.mu.Lock()
	defer l.mu.Unlock()
	io.WriteString(l.out, line)
}

func (l *Logger) Debugf(format string, args ...any) { l.Printf("DEBUG", format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.Printf("INFO", format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.Printf("WARN", format, args...) }
