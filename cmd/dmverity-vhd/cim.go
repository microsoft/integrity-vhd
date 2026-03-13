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
	log "github.com/sirupsen/logrus"
)

type ParentLayers []*cimfs.BlockCIM

func tarToCim(tarReader io.Reader, parentLayers ParentLayers, out string, layerName string) (string, ParentLayers, error) {
	log.Trace("tarToCim called")

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

	log.Tracef("before cimimport.ImportBlockCIMLayerWithOpts for layer %s", layerName)
	size, importErr := cimimport.ImportBlockCIMLayerWithOpts(context.Background(), tarReader, blockCIM, importOpts...)
	log.Tracef("after cimimport.ImportBlockCIMLayerWithOpts for layer %s, size %d", layerName, size)
	if importErr != nil {
		return "", parentLayers, fmt.Errorf("layer (%s): %w", layerName, importErr)
	}

	digest, err := cimimport.GetIntegrityChecksum(context.Background(), blockPath, "")
	if err != nil {
		return "", parentLayers, fmt.Errorf("failed to read integrity_checksum for layer %s: %w", layerName, err)
	}

	parentLayers = append(parentLayers, blockCIM)

	return strings.TrimSpace(string(digest)), parentLayers, nil
}

func sanitizeCimLayerName(name string) string {
	log.Trace("sanitizeCimLayerName called")

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
