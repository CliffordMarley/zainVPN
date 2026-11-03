//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "the zainVPN desktop app runs on Windows only")
	os.Exit(1)
}
