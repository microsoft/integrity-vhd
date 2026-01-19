//go:build !windows
// +build !windows

package main

import (
	"errors"
)

func windowsLayerHasher(layerHashes map[string]string) (LayerProcessor, func() error, error) {
	return nil, nil, errors.New("windows layer hashing is only supported on Windows")
}
