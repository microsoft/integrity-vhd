//go:build !windows
// +build !windows

package main

import (
	"errors"
	"io"
)

type ParentLayers []int

func tarToCim(tarReader io.Reader, parentLayers ParentLayers, out string, layerName string) (string, ParentLayers, error) {
	return "", nil, errors.New("windows layer hashing is only supported on Windows")
}
