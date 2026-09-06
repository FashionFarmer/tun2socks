//go:build unix

package instance

import "golang.org/x/sys/unix"

func duplicateTunFD(fd int) (int, error) { return unix.Dup(fd) }
func closeTunFD(fd int) error            { return unix.Close(fd) }
