package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func parseCreateVhdArgs(ctx *cli.Context) (
	imageName string,
	outDir string,
	platform string,
	verityHashDev bool,
	verityData bool,
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	err error,
) {
	log.Trace("parseCreateVhdArgs called")

	imageName = ctx.String(inputFlag)
	outDir = ctx.String(outputDirFlag)
	platform = ctx.String(platformFlag)
	verityHashDev = ctx.Bool(hashDeviceVhdFlag)
	verityData = ctx.Bool(dataVhdFlag)

	imageFetcher, imageParser, manifestParser, err = getImageParsers(ctx)
	if err != nil {
		return "", "", "", false, false, nil, nil, nil, err
	}

	return
}

func createVhd(
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	imageName string,
	outDir string,
	platform string,
	verityHashDev bool,
	verityData bool,
) error {
	log.Trace("createVhd called")

	// Ensure output directory exists
	err := ensureDirExists(outDir)
	if err != nil {
		return err
	}

	if verityData {
		return saveDirTarAsVhd(imageName, verityHashDev, outDir)
	}

	var layerParser LayerParser
	var tempDirs []string // Track temp directories for cleanup

	if strings.HasPrefix(platform, "linux") {
		log.Debug("creating layer VHDs with dm-verity for Linux")
		layerParser = func(layerID string, layerReader io.Reader) (string, error) {
			return "", createVHDLayer(layerID, layerReader, verityHashDev, outDir)
		}
	} else if strings.HasPrefix(platform, "windows") {
		log.Debug("creating layer CIM files for Windows")
		parentLayers := make(ParentLayers, 0)
		layerParser = func(layerID string, layerReader io.Reader) (string, error) {
			// Sanitize layerID to remove path separators for os.MkdirTemp
			safeLayerID := filepath.Base(layerID)
			cimOut, err := os.MkdirTemp("", safeLayerID)
			if err != nil {
				return "", fmt.Errorf("failed to create temp directory for layer %s: %w", layerID, err)
			}
			tempDirs = append(tempDirs, cimOut)
			var hash string
			hash, parentLayers, err = tarToCim(layerReader, parentLayers, cimOut, layerID)
			return hash, err
		}
	} else {
		return fmt.Errorf("unsupported platform: %s", platform)
	}

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

	// Move the output files to the output directory
	// They can't immediately be in the output directory because they have
	// temporary file names based on the layer id which isn't necessarily
	// the layer digest
	if strings.HasPrefix(platform, "linux") {
		// Move VHD files
		for layerNumber := 0; layerNumber < len(layerDigests); layerNumber++ {
			layerDiffId := layerDiffIds[layerNumber]
			layerDigest := layerDigests[layerNumber]
			// Sanitize the full layer digest path to match the VHD filename created
			sanitisedFileName := sanitiseVHDFilename(layerDigest)

			suffixes := []string{".vhd"}

			for _, srcSuffix := range suffixes {
				src := filepath.Join(os.TempDir(), sanitisedFileName+srcSuffix)
				if _, err := os.Stat(src); os.IsNotExist(err) {
					return fmt.Errorf("layer VHD %s does not exist", src)
				}

				dst := filepath.Join(outDir, layerDiffId+srcSuffix)
				if err := moveFile(src, dst); err != nil {
					return err
				}

				fmt.Fprintf(os.Stdout, "Layer VHD created at %s\n", dst)
			}
		}
	} else if strings.HasPrefix(platform, "windows") {
		// Move CIM files (.bcim)
		for layerNumber := 0; layerNumber < len(layerDigests); layerNumber++ {
			layerDiffId := layerDiffIds[layerNumber]
			tempDir := tempDirs[layerNumber]

			// Find the .bcim file in the temp directory
			files, err := filepath.Glob(filepath.Join(tempDir, "*.bcim"))
			if err != nil {
				return fmt.Errorf("failed to find CIM files: %w", err)
			}
			if len(files) == 0 {
				return fmt.Errorf("no CIM file found in %s", tempDir)
			}

			src := files[0]
			dst := filepath.Join(outDir, layerDiffId+".bcim")
			if err := moveFile(src, dst); err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "Layer CIM created at %s\n", dst)

			// Clean up temp directory
			os.RemoveAll(tempDir)
		}
	}

	return nil
}
