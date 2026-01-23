//go:build !windows
// +build !windows

package main

import (
	"errors"
	"io"
)

func tarToCim(tarReader io.Reader, out string) (string, error) {
	return "", errors.New("windows layer hashing is only supported on Windows")
}
