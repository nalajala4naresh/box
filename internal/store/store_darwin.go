package store

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ensureDataVolume returns a case-sensitive directory for rootfs trees.
// Linux images ship names that differ only by case, which a default
// (case-insensitive) APFS volume silently merges. When $BOX_HOME is not
// already case-sensitive, box keeps its data in a sparse bundle formatted
// Case-sensitive APFS and attaches it on demand (no root needed). APFS
// also gives clonefile(2), which makes snapshots and sandboxes cheap.
func ensureDataVolume(root string) (string, error) {
	data := filepath.Join(root, "data")
	if caseSensitive(root) {
		return data, os.MkdirAll(data, 0o700)
	}
	if isMountPoint(data) {
		if !caseSensitive(data) {
			return "", fmt.Errorf("%s is mounted but not case-sensitive", data)
		}
		return data, nil
	}
	image := filepath.Join(root, "data.sparsebundle")
	if !Exists(image) {
		out, err := exec.Command("hdiutil", "create", "-quiet",
			"-size", "1t", "-type", "SPARSEBUNDLE",
			"-fs", "Case-sensitive APFS", "-volname", "box-data", image).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("create case-sensitive volume %s: %v: %s", image, err, bytes.TrimSpace(out))
		}
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		return "", err
	}
	out, err := exec.Command("hdiutil", "attach", "-quiet", "-nobrowse", "-noautoopen",
		"-mountpoint", data, image).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("attach %s: %v: %s", image, err, bytes.TrimSpace(out))
	}
	if !caseSensitive(data) {
		return "", fmt.Errorf("%s is not case-sensitive after attach", data)
	}
	return data, nil
}

// Clone makes dst a copy-on-write clone of the tree at src (APFS
// clonefile). Extended attributes, which carry guest ownership, come along.
func Clone(src, dst string) error {
	if err := unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW); err != nil {
		return fmt.Errorf("clone %s: %w", src, err)
	}
	return nil
}

// statXattr is where libkrun's macOS virtio-fs keeps guest ownership and
// mode ("uid:gid:0mode"); host files stay owned by the invoking user.
const statXattr = "user.containers.override_stat"

// SetGuestStat records the guest-visible owner and permission bits of a
// host file inside a rootfs.
func SetGuestStat(path string, uid, gid int, mode os.FileMode, isLink bool) error {
	value := []byte(fmt.Sprintf("%d:%d:0%o", uid, gid, unixMode(mode)))
	if isLink {
		return unix.Lsetxattr(path, statXattr, value, 0)
	}
	return unix.Setxattr(path, statXattr, value, 0)
}

// HostPerm is the host-side permission a rootfs entry needs so the VMM,
// running as the invoking user, can always read and update it.
func HostPerm(mode os.FileMode, isDir bool) os.FileMode {
	perm := mode.Perm()
	if isDir {
		return perm | 0o700
	}
	return perm | 0o600
}

// unixMode converts Go's mode bits back to the numeric permission bits
// (including setuid, setgid, and sticky).
func unixMode(mode os.FileMode) uint32 {
	m := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		m |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		m |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		m |= 0o1000
	}
	return m
}
