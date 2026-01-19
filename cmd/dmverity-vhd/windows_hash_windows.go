//go:build windows
// +build windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/pkg/cimfs"
	cimimport "github.com/Microsoft/hcsshim/pkg/ociwclayer/cim"
)

func windowsLayerHasher(layerHashes map[string]string) (LayerProcessor, func() error, error) {
	outDir, err := os.MkdirTemp("", "cimlayer")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	getLayerHash := func(layerDigest string, layerReader io.Reader) error {
		layerFolder := filepath.Join(outDir, layerDigest)
		blockFileName := fmt.Sprintf("%s.bcim", layerDigest)
		cimName := fmt.Sprintf("%s.cim", layerDigest)
		blockPath := filepath.Join(layerFolder, blockFileName)
		integrityPath := filepath.Join(layerFolder, "integrity_checksum")

		blockCIM := &cimfs.BlockCIM{
			Type:      cimfs.BlockCIMTypeSingleFile,
			BlockPath: blockPath,
			CimName:   cimName,
		}

		importOpts := []cimimport.BlockCIMLayerImportOpt{
			cimimport.WithVHDFooter(),
			cimimport.WithLayerIntegrity(),
		}

		_, importErr := cimimport.ImportBlockCIMLayerWithOpts(context.Background(), layerReader, blockCIM, importOpts...)
		if importErr != nil {
			return fmt.Errorf("layer (%s): %w", layerDigest, importErr)
		}

		data, err := os.ReadFile(integrityPath)
		if err != nil {
			return fmt.Errorf("failed to read integrity_checksum for layer %s: %w", layerDigest, err)
		}
		layerHashes[layerDigest] = strings.TrimSpace(string(data))

		return nil
	}

	return getLayerHash, func() error { return os.RemoveAll(outDir) }, nil
}
