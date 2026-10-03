// Package oci pulls container images and flattens them into rootfs trees a
// libkrun VM can boot from.
package oci

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/nalajala4naresh/box/internal/store"
)

// Image is an extracted image.
type Image struct {
	Ref    string   `json:"ref"`
	Digest string   `json:"digest"`
	Env    []string `json:"env"`
	Rootfs string   `json:"-"`
}

// Ensure resolves ref against its registry — always re-checking the
// manifest, so a moved tag is noticed — and extracts the flattened rootfs
// once per manifest digest. Unchanged layers come from the local cache.
func Ensure(ctx context.Context, st *store.Store, ref string, progress func(string)) (Image, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return Image{}, fmt.Errorf("parse image %s: %w", ref, err)
	}
	progress("resolving " + ref)
	img, err := remote.Image(parsed,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: runtime.GOARCH}))
	if err != nil {
		if strings.Contains(err.Error(), "no child with platform") {
			return Image{}, fmt.Errorf("image %s has no linux/%s build; libkrun only runs guests of the host architecture, so set sandbox.image to a linux/%s image", ref, runtime.GOARCH, runtime.GOARCH)
		}
		return Image{}, fmt.Errorf("pull %s: %w", ref, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return Image{}, err
	}
	dir := filepath.Join(st.ImagesDir(), digest.Hex)
	meta := filepath.Join(dir, "image.json")
	if data, err := os.ReadFile(meta); err == nil {
		var out Image
		if json.Unmarshal(data, &out) == nil {
			out.Rootfs = filepath.Join(dir, "rootfs")
			return out, nil
		}
	}

	configFile, err := img.ConfigFile()
	if err != nil {
		return Image{}, fmt.Errorf("image config: %w", err)
	}
	cached := cache.Image(img, cache.NewFilesystemCache(filepath.Join(st.CacheDir(), "layers")))
	layers, err := cached.Layers()
	if err != nil {
		return Image{}, fmt.Errorf("image layers: %w", err)
	}

	tmp := fmt.Sprintf("%s.tmp-%d", dir, os.Getpid())
	store.RemoveAll(tmp)
	rootfs := filepath.Join(tmp, "rootfs")
	if err := os.MkdirAll(rootfs, store.HostPerm(0o755, true)); err != nil {
		return Image{}, err
	}
	if err := store.SetGuestStat(rootfs, 0, 0, 0o755, false); err != nil {
		return Image{}, fmt.Errorf("set guest ownership (does the filesystem support extended attributes?): %w", err)
	}
	for i, layer := range layers {
		size, _ := layer.Size()
		progress(fmt.Sprintf("layer %d/%d · %s", i+1, len(layers), humanBytes(size)))
		rc, err := layer.Uncompressed()
		if err != nil {
			store.RemoveAll(tmp)
			return Image{}, fmt.Errorf("fetch layer %d: %w", i+1, err)
		}
		err = ApplyLayer(rootfs, rc)
		rc.Close()
		if err != nil {
			store.RemoveAll(tmp)
			return Image{}, fmt.Errorf("extract layer %d: %w", i+1, err)
		}
		if ctx.Err() != nil {
			store.RemoveAll(tmp)
			return Image{}, ctx.Err()
		}
	}
	out := Image{Ref: ref, Digest: digest.String(), Env: configFile.Config.Env}
	data, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, "image.json"), data, 0o600); err != nil {
		return Image{}, err
	}
	if store.Exists(dir) {
		store.RemoveAll(dir)
	}
	if err := os.Rename(tmp, dir); err != nil {
		return Image{}, err
	}
	out.Rootfs = filepath.Join(dir, "rootfs")
	return out, nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// ApplyLayer extracts one uncompressed layer tarball over root, honoring
// OCI whiteouts. Paths are resolved inside root, so a symlink in the image
// can never redirect a write onto the host.
func ApplyLayer(root string, r io.Reader) error {
	tr := tar.NewReader(r)
	var deferred []*tar.Header
	buf := make([]byte, 1<<20)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		clean := path.Clean("/" + hdr.Name)
		if clean == "/" {
			if hdr.Typeflag == tar.TypeDir {
				applyMeta(root, hdr, false)
			}
			continue
		}
		dir, base := path.Split(clean)
		parent, err := securejoin.SecureJoin(root, dir)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", clean, err)
		}
		if err := mkdirAllGuest(root, parent); err != nil {
			return err
		}
		if base == ".wh..wh..opq" {
			entries, _ := os.ReadDir(parent)
			for _, entry := range entries {
				store.RemoveAll(filepath.Join(parent, entry.Name()))
			}
			continue
		}
		if hidden, ok := strings.CutPrefix(base, ".wh."); ok {
			store.RemoveAll(filepath.Join(parent, hidden))
			continue
		}
		target := filepath.Join(parent, base)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if info, err := os.Lstat(target); err != nil || !info.IsDir() {
				store.RemoveAll(target)
				if err := os.Mkdir(target, store.HostPerm(0o755, true)); err != nil {
					return err
				}
			}
			os.Chmod(target, store.HostPerm(hdr.FileInfo().Mode(), true))
			applyMeta(target, hdr, false)
		case tar.TypeReg, tar.TypeRegA:
			store.RemoveAll(target)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, store.HostPerm(hdr.FileInfo().Mode(), false))
			if err != nil {
				return err
			}
			_, err = io.CopyBuffer(f, tr, buf)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return fmt.Errorf("write %s: %w", clean, err)
			}
			os.Chmod(target, store.HostPerm(hdr.FileInfo().Mode(), false))
			applyMeta(target, hdr, false)
		case tar.TypeSymlink:
			store.RemoveAll(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
			applyMeta(target, hdr, true)
		case tar.TypeLink:
			if err := link(root, hdr, target); err != nil {
				deferred = append(deferred, hdr)
			}
		case tar.TypeFifo:
			store.RemoveAll(target)
			if err := mkfifo(target); err == nil {
				applyMeta(target, hdr, false)
			}
		default:
			// Device nodes come from the guest's devtmpfs.
		}
	}
	for _, hdr := range deferred {
		clean := path.Clean("/" + hdr.Name)
		dir, base := path.Split(clean)
		parent, err := securejoin.SecureJoin(root, dir)
		if err != nil {
			return err
		}
		if err := link(root, hdr, filepath.Join(parent, base)); err != nil {
			return fmt.Errorf("hard link %s -> %s: %w", clean, hdr.Linkname, err)
		}
	}
	return nil
}

func link(root string, hdr *tar.Header, target string) error {
	linkDir, linkBase := path.Split(path.Clean("/" + hdr.Linkname))
	linkParent, err := securejoin.SecureJoin(root, linkDir)
	if err != nil {
		return err
	}
	source := filepath.Join(linkParent, linkBase)
	if _, err := os.Lstat(source); err != nil {
		return err
	}
	store.RemoveAll(target)
	return os.Link(source, target)
}

// mkdirAllGuest creates missing parents, giving each the root-owned 0755
// a real filesystem would show.
func mkdirAllGuest(root, dir string) error {
	if info, err := os.Lstat(dir); err == nil && info.IsDir() {
		return nil
	}
	var missing []string
	for d := dir; d != root && len(d) > len(root); d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		}
		missing = append(missing, d)
	}
	if err := os.MkdirAll(dir, store.HostPerm(0o755, true)); err != nil {
		return err
	}
	for _, d := range missing {
		store.SetGuestStat(d, 0, 0, 0o755, false)
	}
	return nil
}

func applyMeta(target string, hdr *tar.Header, isLink bool) {
	store.SetGuestStat(target, hdr.Uid, hdr.Gid, hdr.FileInfo().Mode(), isLink)
	mtime := hdr.ModTime
	if mtime.IsZero() {
		mtime = time.Unix(0, 0)
	}
	if isLink {
		lchtimes(target, mtime)
		return
	}
	os.Chtimes(target, mtime, mtime)
}
