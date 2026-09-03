package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

// CreateVhdLayerOutput describes one layer produced by `create --format json`.
type CreateVhdLayerOutput struct {
	Digest         string `json:"digest"`
	DiffID         string `json:"diff_id"`
	VhdPath        string `json:"vhd_path"`
	VerityRootHash string `json:"verity_root_hash,omitempty"`
}

// CreateVhdOutput is the top-level `create --format json` document.
type CreateVhdOutput struct {
	SchemaVersion string                  `json:"schema_version"`
	ImageReference string                 `json:"image_reference"`
	Layers         []CreateVhdLayerOutput `json:"layers"`
}

const createVhdOutputSchemaVersion = "1"

func parseCreateVhdArgs(ctx *cli.Context) (
	imageName string,
	outDir string,
	platform string,
	verityHashDev bool,
	verityData bool,
	formatJSON bool,
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
	formatJSON = ctx.String(formatFlag) == formatJSONValue

	imageFetcher, imageParser, manifestParser, err = getImageParsers(ctx)
	if err != nil {
		return "", "", "", false, false, false, nil, nil, nil, err
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
	formatJSON bool,
) error {
	log.Trace("createVhd called")

	// Ensure output directory exists
	err := ensureDirExists(outDir)
	if err != nil {
		return err
	}

	if verityData {
		rootHash, err := saveDirTarAsVhd(imageName, verityHashDev, outDir)
		if err != nil {
			return err
		}
		if formatJSON {
			sanitisedDirName := sanitiseVHDFilename(imageName)
			return printCreateVhdJSON(imageName, []CreateVhdLayerOutput{{
				VhdPath:        filepath.Join(outDir, sanitisedDirName+".vhd"),
				VerityRootHash: rootHash,
			}})
		}
		return nil
	}

	var layerParser LayerParser
	var tempDirs []string // Track temp directories for cleanup

	if strings.HasPrefix(platform, "linux") {
		log.Debug("creating layer VHDs with dm-verity for Linux")
		layerParser = func(layerID string, layerReader io.Reader) (string, error) {
			return createVHDLayer(layerID, layerReader, verityHashDev, outDir)
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

	layerDigestToHash, manifestFiles, err := imageParser(image, layerParser)
	if err != nil {
		return err
	}

	layerDiffIds, layerDigests, err := manifestParser(manifestFiles)
	if err != nil {
		return err
	}

	var jsonLayers []CreateVhdLayerOutput

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

				jsonLayers = append(jsonLayers, CreateVhdLayerOutput{
					Digest:         layerDigest,
					DiffID:         layerDiffId,
					VhdPath:        dst,
					VerityRootHash: layerDigestToHash[layerDigest],
				})
			}
		}
	} else if strings.HasPrefix(platform, "windows") {
		// Move CIM files (.bcim)
		for layerNumber := 0; layerNumber < len(layerDigests); layerNumber++ {
			layerDiffId := layerDiffIds[layerNumber]
			layerDigest := layerDigests[layerNumber]
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

			jsonLayers = append(jsonLayers, CreateVhdLayerOutput{
				Digest:         layerDigest,
				DiffID:         layerDiffId,
				VhdPath:        dst,
				VerityRootHash: layerDigestToHash[layerDigest],
			})

			// Clean up temp directory
			os.RemoveAll(tempDir)
		}
	}

	if formatJSON {
		return printCreateVhdJSON(imageName, jsonLayers)
	}

	return nil
}

func printCreateVhdJSON(imageName string, layers []CreateVhdLayerOutput) error {
	output := CreateVhdOutput{
		SchemaVersion:  createVhdOutputSchemaVersion,
		ImageReference: imageName,
		Layers:         layers,
	}
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON output: %w", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", jsonData)
	return nil
}

