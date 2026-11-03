//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "zainVPN client runs on Windows only")
	os.Exit(1)
}
