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

func parseRoothashArgs(ctx *cli.Context) (
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	layerParser LayerParser,
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
	} else if strings.HasPrefix(platform, "windows") {
		var hash string
		parentLayers := make(ParentLayers, 0)
		layerParser = func(layerID string, layerReader io.Reader) (string, error) {
			cimOut, err := os.MkdirTemp("", layerID)
			hash, parentLayers, err = tarToCim(layerReader, parentLayers, cimOut, layerID)
			return hash, err
		}
	}

	return
}

func roothash(
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	layerParser LayerParser,
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
	return nil
}
