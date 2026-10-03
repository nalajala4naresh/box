package shell

import "testing"

func TestQuotesShellArgs(t *testing.T) {
	if got := Join([]string{"omp"}); got != "omp" {
		t.Fatalf("got %q", got)
	}
	if got := Join([]string{"omp", "say hi"}); got != "omp 'say hi'" {
		t.Fatalf("got %q", got)
	}
	if got := Quote(""); got != "''" {
		t.Fatalf("got %q", got)
	}
	if got := Quote("it's"); got != `'it'"'"'s'` {
		t.Fatalf("got %q", got)
	}
	if got := Quote("/home/user/workspace"); got != "/home/user/workspace" {
		t.Fatalf("got %q", got)
	}
}
