package sandbox

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nalajala4naresh/box/internal/store"
)

// Snapshot is a frozen rootfs that sandboxes and later layers clone from.
type Snapshot struct {
	Name string `json:"name"`
	// Digest identifies this particular build of the snapshot. A rebuild
	// under the same name gets a new digest, which is what makes sessions
	// cloned from the old build notice and recreate.
	Digest   string    `json:"digest"`
	Parent   string    `json:"parent,omitempty"`
	ImageEnv []string  `json:"image_env,omitempty"`
	Created  time.Time `json:"created"`
}

func snapshotMeta(st *store.Store, name string) string {
	return filepath.Join(st.SnapshotDir(name), "snapshot.json")
}

// SnapshotRootfs is a snapshot's frozen root filesystem.
func SnapshotRootfs(st *store.Store, name string) string {
	return filepath.Join(st.SnapshotDir(name), "rootfs")
}

// OpenSnapshot loads a snapshot by name.
func OpenSnapshot(st *store.Store, name string) (Snapshot, error) {
	data, err := os.ReadFile(snapshotMeta(st, name))
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s not found", name)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s: %w", name, err)
	}
	if !store.Exists(SnapshotRootfs(st, name)) {
		return Snapshot{}, fmt.Errorf("snapshot %s has no rootfs", name)
	}
	return snap, nil
}

// SnapshotFromSandbox freezes a stopped sandbox's rootfs as name,
// replacing any previous snapshot of that name (force). The sandbox's
// rootfs moves into the snapshot, so the sandbox must be removed after.
func SnapshotFromSandbox(st *store.Store, name, sandboxName string) (Snapshot, error) {
	spec, err := LoadSpec(st, sandboxName)
	if err != nil {
		return Snapshot{}, err
	}
	if StatusOf(st, sandboxName) != Stopped {
		return Snapshot{}, fmt.Errorf("sandbox %s is still running", sandboxName)
	}
	parentDigest := ""
	if parent, err := OpenSnapshot(st, spec.Base); err == nil {
		parentDigest = parent.Digest
	}
	created := time.Now().UTC()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s", name, created.UnixNano(), spec.Base, parentDigest)))
	snap := Snapshot{
		Name:     name,
		Digest:   fmt.Sprintf("sha256:%x", sum),
		Parent:   spec.Base,
		ImageEnv: spec.ImageEnv,
		Created:  created,
	}

	staging := st.SnapshotDir(name) + ".staging"
	store.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return Snapshot{}, err
	}
	// The wrap plumbing under /.wrap is rewritten on every boot; drop it
	// so it never rides along into a shared snapshot.
	rootfs := RootfsPath(st, sandboxName)
	os.Remove(filepath.Join(rootfs, ".wrap", "boot.json"))
	if err := os.Rename(rootfs, filepath.Join(staging, "rootfs")); err != nil {
		store.RemoveAll(staging)
		return Snapshot{}, fmt.Errorf("freeze %s: %w", sandboxName, err)
	}
	data, _ := json.MarshalIndent(snap, "", "  ")
	if err := os.WriteFile(filepath.Join(staging, "snapshot.json"), data, 0o600); err != nil {
		return Snapshot{}, err
	}
	// Promote only once complete: an interrupted rebuild leaves the old
	// snapshot in place.
	old := st.SnapshotDir(name) + ".old"
	store.RemoveAll(old)
	if store.Exists(st.SnapshotDir(name)) {
		if err := os.Rename(st.SnapshotDir(name), old); err != nil {
			return Snapshot{}, err
		}
	}
	if err := os.Rename(staging, st.SnapshotDir(name)); err != nil {
		return Snapshot{}, err
	}
	store.RemoveAll(old)
	return snap, nil
}
