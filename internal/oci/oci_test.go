package oci

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type entry struct {
	name     string
	typ      byte
	body     string
	link     string
	mode     int64
	uid, gid int
}

func layer(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
			if e.typ == tar.TypeDir {
				mode = 0o755
			}
		}
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: mode, Linkname: e.link, Uid: e.uid, Gid: e.gid, Size: int64(len(e.body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return &buf
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestApplyLayersWithWhiteoutsAndLinks(t *testing.T) {
	root := t.TempDir()
	base := layer(t,
		entry{name: "etc/", typ: tar.TypeDir},
		entry{name: "etc/os-release", typ: tar.TypeReg, body: "arch"},
		entry{name: "usr/lib/", typ: tar.TypeDir},
		entry{name: "usr/lib/libx.so", typ: tar.TypeReg, body: "lib"},
		entry{name: "lib", typ: tar.TypeSymlink, link: "usr/lib"},
		entry{name: "opt/cache/", typ: tar.TypeDir},
		entry{name: "opt/cache/old", typ: tar.TypeReg, body: "old"},
		entry{name: "usr/bin/sudo", typ: tar.TypeReg, body: "sudo", mode: 0o4755},
		entry{name: "home/user/.zshrc", typ: tar.TypeReg, body: "rc", uid: 1000, gid: 1000},
	)
	if err := ApplyLayer(root, base); err != nil {
		t.Fatal(err)
	}
	top := layer(t,
		entry{name: "etc/.wh.os-release", typ: tar.TypeReg},
		entry{name: "opt/cache/.wh..wh..opq", typ: tar.TypeReg},
		entry{name: "opt/cache/new", typ: tar.TypeReg, body: "new"},
		// Through the lib -> usr/lib symlink.
		entry{name: "lib/liby.so", typ: tar.TypeReg, body: "y"},
		entry{name: "usr/lib/libx.so.1", typ: tar.TypeLink, link: "usr/lib/libx.so"},
	)
	if err := ApplyLayer(root, top); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/os-release")); err == nil {
		t.Fatal("whiteout must delete the lower file")
	}
	if _, err := os.Lstat(filepath.Join(root, "opt/cache/old")); err == nil {
		t.Fatal("opaque dir must hide lower entries")
	}
	if mustRead(t, filepath.Join(root, "opt/cache/new")) != "new" {
		t.Fatal("upper entry in opaque dir")
	}
	if mustRead(t, filepath.Join(root, "usr/lib/liby.so")) != "y" {
		t.Fatal("write through relative symlink must land under usr/lib")
	}
	a, _ := os.Stat(filepath.Join(root, "usr/lib/libx.so"))
	b, _ := os.Stat(filepath.Join(root, "usr/lib/libx.so.1"))
	if !os.SameFile(a, b) {
		t.Fatal("hard link")
	}
	if runtime.GOOS == "darwin" {
		for path, want := range map[string]string{
			"usr/bin/sudo":     "0:0:04755",
			"home/user/.zshrc": "1000:1000:0644",
			"home/user":        "0:0:0755",
			"lib":              "0:0:0644",
		} {
			buf := make([]byte, 64)
			n, err := unix.Lgetxattr(filepath.Join(root, path), "user.containers.override_stat", buf)
			if err != nil || string(buf[:n]) != want {
				t.Fatalf("%s: %q %v want %q", path, buf[:n], err, want)
			}
		}
	}
}

func TestApplyLayerCannotEscapeRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "rootfs")
	os.Mkdir(root, 0o755)
	outside := filepath.Join(parent, "outside")
	os.Mkdir(outside, 0o755)
	evil := layer(t,
		entry{name: "escape", typ: tar.TypeSymlink, link: outside},
		entry{name: "escape/pwned", typ: tar.TypeReg, body: "x"},
		entry{name: "../dotdot", typ: tar.TypeReg, body: "x"},
		entry{name: "up", typ: tar.TypeSymlink, link: "../../.."},
		entry{name: "up/also-pwned", typ: tar.TypeReg, body: "x"},
	)
	if err := ApplyLayer(root, evil); err != nil && !strings.Contains(err.Error(), "resolve") {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("a symlink redirected a write outside the rootfs")
	}
	for _, name := range []string{"dotdot", "also-pwned"} {
		if _, err := os.Lstat(filepath.Join(parent, name)); err == nil {
			t.Fatalf("%s escaped the rootfs", name)
		}
	}
}
