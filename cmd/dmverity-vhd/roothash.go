package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type MergedHashGenerator func(layerCount int) (string, error)

func parseRoothashArgs(ctx *cli.Context) (
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	layerParser LayerParser,
	mergedHashGenerator MergedHashGenerator,
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
	} else if strings.HasPrefix(platform, "windows") {
		parentLayers := make(ParentLayers, 0)
		layerParser = func(layerID string, layerReader io.Reader) (string, error) {
			cimOut, err := os.MkdirTemp("", layerID)
			if err != nil {
				return "", fmt.Errorf("failed to create temp directory for layer %s: %w", layerID, err)
			}
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
			mergedOut, err := os.MkdirTemp("", "merged_cim")
			if err != nil {
				return "", fmt.Errorf("failed to create temp directory for merged CIM: %w", err)
			}
			return generateMergedCim(parentLayers, mergedOut, "merged")
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
) error {
	log.Trace("roothash called")

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

	// Print the layer number to layer hash
	var missingLayers []int
	for layerNumber := 0; layerNumber < len(layerDigests); layerNumber++ {
		hash, ok := layerDigestToHash[layerDigests[layerNumber]]
		if !ok {
			missingLayers = append(missingLayers, layerNumber)
			continue
		}
		fmt.Fprintf(os.Stdout, "Layer %d root hash: %s\n", layerNumber, hash)
	}
	if len(missingLayers) > 0 {
		return fmt.Errorf("missing root hashes for layers: %v", missingLayers)
	}

	// Generate and print merged hash if applicable
	if mergedHashGenerator != nil {
		mergedHash, err := mergedHashGenerator(len(layerDigests))
		if err != nil {
			return fmt.Errorf("failed to generate merged hash: %w", err)
		}
		if mergedHash != "" {
			fmt.Fprintf(os.Stdout, "Merged layer hash: %s\n", mergedHash)
		}
	}

	return nil
}
