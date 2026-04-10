package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type RootHashOutput struct {
	Layers     []string `json:"layers"`
	MountedCim []string `json:"mounted_cim,omitempty"`
}

type MergedHashGenerator func(layerCount int) (string, error)

func parseRoothashArgs(ctx *cli.Context) (
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	layerParser LayerParser,
	mergedHashGenerator MergedHashGenerator,
	cleanupFunc func(),
	err error,
) {
	log.Trace("parseRoothashArgs called")

	imageFetcher, imageParser, manifestParser, err = getImageParsers(ctx)
	if err != nil {
		return
	}

	platform := ctx.String(platformFlag)
	if strings.HasPrefix(platform, "linux") {
		layerParser = func(layerID string, layerReader io.Reader) (string, error) {
			log.Tracef("linux LayerProcessor before tar2ext4.ConvertAndComputeRootDigest for layer %s", layerID)
			hash, err := tar2ext4.ConvertAndComputeRootDigest(layerReader)
			log.Tracef("linux LayerProcessor before tar2ext4.ConvertAndComputeRootDigest for layer %s", layerID)
			return hash, err
		}
		mergedHashGenerator = func(layerCount int) (string, error) {
			return "", nil // No merged hash for Linux
		}
		cleanupFunc = func() {} // No cleanup needed for Linux
	} else if strings.HasPrefix(platform, "windows") {
		parentLayers := make(ParentLayers, 0)
		var tempDirs []string // Track temp directories for cleanup
		var mergedTempDir string

		layerParser = func(layerID string, layerReader io.Reader) (string, error) {
			// Sanitize layerID to remove path separators for os.MkdirTemp
			// layerID might be like "blobs/sha256/hash" so we extract just the base name
			safeLayerID := filepath.Base(layerID)
			cimOut, err := os.MkdirTemp("", safeLayerID)
			if err != nil {
				return "", fmt.Errorf("failed to create temp directory for layer %s: %w", layerID, err)
			}
			tempDirs = append(tempDirs, cimOut) // Track for cleanup
			var hash string
			hash, parentLayers, err = tarToCim(layerReader, parentLayers, cimOut, layerID)
			return hash, err
		}

		mergedHashGenerator = func(layerCount int) (string, error) {
			if layerCount <= 1 {
				log.Trace("Skipping merged CIM generation: only one layer")
				return "", nil
			}
			log.Tracef("Generating merged CIM for %d layers", layerCount)
			// Create a new temp directory for the merged CIM
			var err error
			mergedTempDir, err = os.MkdirTemp("", "merged_cim")
			if err != nil {
				return "", fmt.Errorf("failed to create temp directory for merged CIM: %w", err)
			}
			// Generate merged CIM - needs to read from layer temp dirs
			return generateMergedCim(parentLayers, mergedTempDir, "merged")
		}

		// Cleanup function that will be called by roothash() via defer
		cleanupFunc = func() {
			// Clean up merged temp dir if it was created
			if mergedTempDir != "" {
				if err := os.RemoveAll(mergedTempDir); err != nil {
					log.Warnf("Failed to remove merged temp directory %s: %v", mergedTempDir, err)
				}
			}
			// Clean up all layer temp directories
			for _, dir := range tempDirs {
				if err := os.RemoveAll(dir); err != nil {
					log.Warnf("Failed to remove temp directory %s: %v", dir, err)
				}
			}
		}
	}

	return
}

func roothash(
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	layerParser LayerParser,
	mergedHashGenerator MergedHashGenerator,
	cleanupFunc func(),
	platform string,
) error {
	log.Trace("roothash called")

	// Ensure cleanup always happens, even on early returns or errors
	defer cleanupFunc()

	image, err := imageFetcher()
	if err != nil {
		return err
	}

	layerDigestToHash, manifests, err := imageParser(image, layerParser)
	if err != nil {
		return err
	}

	_, layerDigests, err := manifestParser(manifests)
	if err != nil {
		return err
	}

	// Collect layer hashes in order
	var layerHashes []string
	var missingLayers []int
	for layerNumber := 0; layerNumber < len(layerDigests); layerNumber++ {
		hash, ok := layerDigestToHash[layerDigests[layerNumber]]
		if !ok {
			missingLayers = append(missingLayers, layerNumber)
			continue
		}
		layerHashes = append(layerHashes, hash)
	}
	if len(missingLayers) > 0 {
		return fmt.Errorf("missing root hashes for layers: %v", missingLayers)
	}

	// Generate merged hash if applicable
	var mergedHash string
	if mergedHashGenerator != nil {
		mergedHash, err = mergedHashGenerator(len(layerDigests))
		if err != nil {
			return fmt.Errorf("failed to generate merged hash: %w", err)
		}
	}

	// Output format depends on platform
	output := RootHashOutput{
		Layers: layerHashes,
	}

	if strings.HasPrefix(platform, "windows") {
		// Add mounted_cim for Windows: either merged hash or single layer hash
		if mergedHash != "" {
			output.MountedCim = []string{mergedHash}
		} else if len(layerHashes) == 1 {
			output.MountedCim = []string{layerHashes[0]}
		}
	}
	// Both Linux and Windows output JSON
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON output: %w", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", jsonData)

	return nil
}
