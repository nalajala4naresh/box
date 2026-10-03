package methods

import "testing"

func TestParsesOmpSelectors(t *testing.T) {
	cases := map[string]Selector{
		"src/main.rs:5:2":                   {Path: "/home/user/workspace/src/main.rs", Lines: LineSpec{Kind: Count, Start: 5, Count: 2}},
		"/home/user/workspace/foo.rs:10-12": {Path: "/home/user/workspace/foo.rs", Lines: LineSpec{Kind: Range, Start: 10, End: 12}},
		"README.md:3":                       {Path: "/home/user/workspace/README.md", Lines: LineSpec{Kind: From, Start: 3}},
		"notes.txt":                         {Path: "/home/user/workspace/notes.txt", Lines: LineSpec{Kind: All}},
		"weird:name:x":                      {Path: "/home/user/workspace/weird:name:x", Lines: LineSpec{Kind: All}},
		"f:0":                               {Path: "/home/user/workspace/f:0", Lines: LineSpec{Kind: All}},
		"f:9-3":                             {Path: "/home/user/workspace/f:9-3", Lines: LineSpec{Kind: All}},
	}
	for raw, want := range cases {
		if got := ParseSelector(raw); got != want {
			t.Errorf("%q: got %+v want %+v", raw, got, want)
		}
	}
	if ParseSelector(".").Path != "/home/user/workspace" {
		t.Fatal("dot is the workspace")
	}
}

func TestReadScriptUsesSedCount(t *testing.T) {
	if got := ReadScript(ParseSelector("file:5:2")); got != "sed -n '5,6p' -- /home/user/workspace/file" {
		t.Fatal(got)
	}
	if got := ReadScript(ParseSelector("file:5")); got != "tail -n +5 -- /home/user/workspace/file" {
		t.Fatal(got)
	}
}

func TestParsesMethods(t *testing.T) {
	if m, ok := Parse([]string{"ls"}); !ok || m.Kind != Ls {
		t.Fatal("ls")
	}
	if _, ok := Parse([]string{"grep"}); ok {
		t.Fatal("grep needs a pattern")
	}
	if m, ok := Parse([]string{"grep", "foo", "src"}); !ok || m.Kind != Grep || m.Pattern != "foo" {
		t.Fatal("grep")
	}
	if _, ok := Parse([]string{"omp"}); ok {
		t.Fatal("omp is not a method")
	}
	if _, ok := Parse([]string{"bash"}); ok {
		t.Fatal("bash needs a script")
	}
	if m, ok := Parse([]string{"bash", "uname", "-a"}); !ok || m.Script != "uname -a" {
		t.Fatal("bash script")
	}
	if m, _ := Parse([]string{"write", "notes.md", "a", "b"}); m.Path != "/home/user/workspace/notes.md" || *m.Content != "a b" {
		t.Fatal("write content")
	}
	if m, _ := Parse([]string{"write", "notes.md"}); m.Content != nil {
		t.Fatal("write without content reads stdin")
	}
}

func TestScripts(t *testing.T) {
	if got := lsScript(nil); got != "ls -la -- /home/user/workspace" {
		t.Fatal(got)
	}
	if got := lsScript([]string{"-la"}); got != "ls -la -- /home/user/workspace" {
		t.Fatal(got)
	}
	if got := lsScript([]string{"src", "-R"}); got != "ls -la -- /home/user/workspace/src -R" {
		t.Fatal(got)
	}
	if got := grepScript("TODO x", []string{"src", "-i"}); got != "grep -n -R -- 'TODO x' /home/user/workspace/src -i" {
		t.Fatal(got)
	}
	if got := findScript([]string{"-name", "*.md"}); got != "find /home/user/workspace -name '*.md'" {
		t.Fatal(got)
	}
	if got := findScript([]string{"src", "-name", "*.rs"}); got != "find /home/user/workspace/src -name '*.rs'" {
		t.Fatal(got)
	}
}
