package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func parseCreateVhdArgs(ctx *cli.Context) (
	imageName string,
	outDir string,
	verityHashDev bool,
	verityData bool,
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	err error,
) {

	imageName = ctx.String(inputFlag)
	outDir = ctx.String(outputDirFlag)
	verityHashDev = ctx.Bool(hashDeviceVhdFlag)
	verityData = ctx.Bool(dataVhdFlag)

	imageFetcher, imageParser, manifestParser, err = getImageParsers(ctx)
	if err != nil {
		return "", "", false, false, nil, nil, nil, err
	}

	return
}

func createVhd(
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	imageName string,
	outDir string,
	verityHashDev bool,
	verityData bool,
) error {

	// Ensure output directory exists
	err := ensureDirExists(outDir)
	if err != nil {
		return err
	}

	if verityData {
		return saveDirTarAsVhd(imageName, verityHashDev, outDir)
	}

	layerParser := func(layerID string, layerReader io.Reader) (string, error) {
		return "", createVHDLayer(layerID, layerReader, verityHashDev, outDir)
	}

	log.Debug("creating layer VHDs with dm-verity")
	image, err := imageFetcher()
	if err != nil {
		return err
	}

	_, manifestFiles, err := imageParser(image, layerParser)
	if err != nil {
		return err
	}

	layerDiffIds, layerDigests, err := manifestParser(manifestFiles)
	if err != nil {
		return err
	}

	// Move the VHDs to the output directory
	// They can't immediately be in the output directory because they have
	// temporary file names based on the layer id which isn't necessarily
	// the layer digest
	for layerNumber := 0; layerNumber < len(layerDigests); layerNumber++ {
		layerDigest := layerDiffIds[layerNumber]
		layerID := layerDigests[layerNumber]
		sanitisedFileName := sanitiseVHDFilename(layerID)

		suffixes := []string{".vhd"}

		for _, srcSuffix := range suffixes {
			src := filepath.Join(os.TempDir(), sanitisedFileName+srcSuffix)
			if _, err := os.Stat(src); os.IsNotExist(err) {
				return fmt.Errorf("layer VHD %s does not exist", src)
			}

			dst := filepath.Join(outDir, layerDigest+srcSuffix)
			if err := moveFile(src, dst); err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "Layer VHD created at %s\n", dst)
		}

	}
	return nil
}
