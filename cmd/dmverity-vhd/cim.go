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

type ParentLayers []*cimfs.BlockCIM

func tarToCim(tarReader io.Reader, parentLayers ParentLayers, out string, layerName string) (string, ParentLayers, error) {

	// If no out path is given, use a temp directory
	var err error
	if out == "" {
		out, err = os.MkdirTemp("", "cim")
		if err != nil {
			return "", parentLayers, fmt.Errorf("failed to create temp directory: %w", err)
		}
	}

	if layerName == "" {
		layerName = filepath.Base(out)
	}
	layerName = sanitizeCimLayerName(layerName)
	blockFileName := fmt.Sprintf("%s.bcim", layerName)
	cimName := fmt.Sprintf("%s.cim", layerName)
	blockPath := filepath.Join(out, blockFileName)
	integrityPath := filepath.Join(out, "integrity_checksum")

	blockCIM := &cimfs.BlockCIM{
		Type:      cimfs.BlockCIMTypeSingleFile,
		BlockPath: blockPath,
		CimName:   cimName,
	}

	importOpts := []cimimport.BlockCIMLayerImportOpt{
		cimimport.WithParentLayers(parentLayers),
		cimimport.WithVHDFooter(),
		cimimport.WithLayerIntegrity(),
	}

	_, importErr := cimimport.ImportBlockCIMLayerWithOpts(context.Background(), tarReader, blockCIM, importOpts...)
	if importErr != nil {
		return "", parentLayers, fmt.Errorf("layer (%s): %w", layerName, importErr)
	}

	data, err := os.ReadFile(integrityPath)
	if err != nil {
		return "", parentLayers, fmt.Errorf("failed to read integrity_checksum for layer %s: %w", layerName, err)
	}

	parentLayers = append(parentLayers, blockCIM)

	return strings.TrimSpace(string(data)), parentLayers, nil
}

func sanitizeCimLayerName(name string) string {
	name = filepath.Base(name)
	if idx := strings.LastIndex(name, ":"); idx != -1 {
		name = name[idx+1:]
	}
	replacer := strings.NewReplacer(
		":", "_",
		"<", "_",
		">", "_",
		"\"", "_",
		"/", "_",
		"\\", "_",
		"|", "_",
		"?", "_",
		"*", "_",
	)
	name = replacer.Replace(name)
	if name == "" {
		return "layer"
	}
	return name
}
