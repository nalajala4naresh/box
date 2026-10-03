// Command wrap runs commands and coding agents in a disposable microVM
// built around the folder you are in, on libkrun.
package main

import (
	"fmt"
	"os"

	"github.com/nalajala4naresh/box/internal/app"
	"github.com/nalajala4naresh/box/internal/vm"
)

func main() {
	// `wrap __vm <sandbox>` is the detached VM process wrap spawns for
	// itself; libkrun takes the process over from there.
	if len(os.Args) == 3 && os.Args[1] == "__vm" {
		if err := vm.Main(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "wrap vm: %v\n", err)
			os.Exit(1)
		}
		return
	}
	os.Exit(app.Main(os.Args[1:]))
}
