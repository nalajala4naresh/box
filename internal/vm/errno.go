package vm

import "syscall"

// errNoSys is what libkrun-go returns for features compiled out by build
// tags (e.g. networking without krun_net).
var errNoSys error = syscall.ENOSYS
