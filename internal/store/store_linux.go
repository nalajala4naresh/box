package store

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ensureDataVolume needs nothing special: Linux filesystems are
// case-sensitive.
func ensureDataVolume(root string) (string, error) {
	data := filepath.Join(root, "data")
	return data, os.MkdirAll(data, 0o700)
}

// Clone copies the tree at src to dst, reflinking where the filesystem
// supports it.
func Clone(src, dst string) error {
	out, err := exec.Command("cp", "-a", "--reflink=auto", src, dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("clone %s: %v: %s", src, err, bytes.TrimSpace(out))
	}
	return nil
}

// SetGuestStat applies real ownership: libkrun's Linux virtio-fs passes
// host ownership through. Without root the host user keeps ownership.
func SetGuestStat(path string, uid, gid int, mode os.FileMode, isLink bool) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := os.Lchown(path, uid, gid); err != nil {
		return err
	}
	if isLink {
		return nil
	}
	return os.Chmod(path, mode)
}

// HostPerm keeps the image's permissions when ownership is real, and
// guarantees owner access otherwise.
func HostPerm(mode os.FileMode, isDir bool) os.FileMode {
	if os.Geteuid() == 0 {
		return mode.Perm()
	}
	if isDir {
		return mode.Perm() | 0o700
	}
	return mode.Perm() | 0o600
}
