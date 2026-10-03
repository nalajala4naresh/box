package oci

import (
	"time"

	"golang.org/x/sys/unix"
)

func mkfifo(path string) error { return unix.Mkfifo(path, 0o644) }

func lchtimes(path string, t time.Time) {
	ts := unix.NsecToTimespec(t.UnixNano())
	unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
}
