// Package store owns box's on-disk state: extracted images, layer
// snapshots, per-workspace sandboxes, and the runtime sockets of running
// VMs.
//
//	$BOX_HOME (default ~/.box)
//	├── data/        case-sensitive volume (a sparse bundle on macOS)
//	│   ├── images/<digest>/rootfs
//	│   ├── snapshots/<name>/rootfs + snapshot.json
//	│   ├── sandboxes/<name>/rootfs + sandbox.json + logs/
//	│   └── cache/   compressed OCI layers
//	├── ca/          box's TLS interception CA (key never leaves the host)
//	└── run/<name>/  agent.sock, ctl.sock, vm.pid (short paths for sun_path)
//
// Snapshots and sandboxes are copy-on-write clones of their parent rootfs,
// so a new workspace VM costs metadata, not a copy of the image.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Store is the resolved on-disk layout.
type Store struct {
	Root string
	Data string
}

// Open resolves the layout and prepares the case-sensitive data volume.
func Open() (*Store, error) {
	root := os.Getenv("BOX_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("home directory: %w", err)
		}
		root = filepath.Join(home, ".box")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	data, err := ensureDataVolume(root)
	if err != nil {
		return nil, err
	}
	s := &Store{Root: root, Data: data}
	for _, dir := range []string{s.ImagesDir(), s.SnapshotsDir(), s.SandboxesDir(), s.CacheDir(), s.CADir(), filepath.Join(root, "run")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// OpenExisting resolves the layout without creating or mounting anything;
// it fails when the store was never set up.
func OpenExisting() (*Store, error) {
	root := os.Getenv("BOX_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(home, ".box")
	}
	if _, err := os.Stat(root); err != nil {
		return nil, err
	}
	return Open()
}

func (s *Store) ImagesDir() string    { return filepath.Join(s.Data, "images") }
func (s *Store) SnapshotsDir() string { return filepath.Join(s.Data, "snapshots") }
func (s *Store) SandboxesDir() string { return filepath.Join(s.Data, "sandboxes") }
func (s *Store) CacheDir() string     { return filepath.Join(s.Data, "cache") }
func (s *Store) CADir() string        { return filepath.Join(s.Root, "ca") }

func (s *Store) SnapshotDir(name string) string { return filepath.Join(s.SnapshotsDir(), name) }
func (s *Store) SandboxDir(name string) string  { return filepath.Join(s.SandboxesDir(), name) }
func (s *Store) RunDir(name string) string      { return filepath.Join(s.Root, "run", name) }

// caseSensitive probes whether dir distinguishes names by case.
func caseSensitive(dir string) bool {
	probe := filepath.Join(dir, fmt.Sprintf(".box-case-probe-%d-A", os.Getpid()))
	f, err := os.Create(probe)
	if err != nil {
		return false
	}
	f.Close()
	defer os.Remove(probe)
	lower := filepath.Join(dir, fmt.Sprintf(".box-case-probe-%d-a", os.Getpid()))
	_, err = os.Lstat(lower)
	return errors.Is(err, os.ErrNotExist)
}

func isMountPoint(path string) bool {
	var st, parent unix.Stat_t
	if unix.Stat(path, &st) != nil || unix.Stat(filepath.Dir(path), &parent) != nil {
		return false
	}
	return st.Dev != parent.Dev
}

// Lock takes an exclusive advisory lock on path, creating it.
func Lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}

// RemoveAll deletes a tree, first restoring owner permissions anywhere the
// guest left a directory unwritable.
func RemoveAll(path string) error {
	if err := os.RemoveAll(path); err == nil {
		return nil
	}
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			os.Chmod(p, info.Mode().Perm()|0o700)
		}
		return nil
	})
	return os.RemoveAll(path)
}

// Exists reports whether path exists.
func Exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// WriteRootFile writes a file into a rootfs at guestPath with the given
// guest ownership. It is for box's own files under /.box, written before
// the VM boots.
func WriteRootFile(rootfs, guestPath string, data []byte, mode os.FileMode, uid, gid int) error {
	path := filepath.Join(rootfs, filepath.Clean("/"+guestPath))
	parent := filepath.Dir(path)
	if info, err := os.Lstat(parent); err == nil && !info.IsDir() {
		// Never write through a guest-planted symlink.
		os.Remove(parent)
	}
	if err := os.MkdirAll(parent, HostPerm(0o755, true)); err != nil {
		return err
	}
	if err := SetGuestStat(parent, 0, 0, 0o755, false); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, HostPerm(mode, false)); err != nil {
		return err
	}
	if err := os.Chmod(tmp, HostPerm(mode, false)); err != nil {
		return err
	}
	if err := SetGuestStat(tmp, uid, gid, mode, false); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
