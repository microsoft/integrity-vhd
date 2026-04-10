package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func parseHashLayerArgs(ctx *cli.Context) (tarPath string, platform string, err error) {
	tarPath = ctx.String(inputFlag)
	platform = ctx.String(platformFlag)
	return
}

func hashLayer(tarPath string, platform string) (string, error) {
	log.Trace("hashLayer called")

	tarReader, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer tarReader.Close()

	entryReader, closer, err := decompressIfNeeded(tarReader)
	if err != nil {
		return "", err
	}
	if closer != nil {
		defer closer.Close()
	}

	entryReader, isTar := isTar(entryReader)
	if !isTar {
		return "", fmt.Errorf("input file is not a tar archive")
	}

	var hash string
	if strings.HasPrefix(platform, "linux") {
		log.Trace("Using tar2ext4 ConvertAndComputeRootDigest")
		hash, err = tar2ext4.ConvertAndComputeRootDigest(entryReader)
	} else if strings.HasPrefix(platform, "windows") {
		cimOut, err := os.MkdirTemp("", filepath.Base(tarPath))
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(cimOut) // Clean up temp directory
		parentLayers := make(ParentLayers, 0)
		log.Trace("tar2cim")
		hash, _, err = tarToCim(entryReader, parentLayers, cimOut, filepath.Base(tarPath))
	}
	if err != nil {
		return "", err
	}
	log.Tracef("done hashLayer: %s", hash)
	return hash, nil
}

func parseTar2HashedArgs(ctx *cli.Context) (tarPath string, platform string, err error) {
	log.Trace("parseHashLayerArgs called")

	tarPath = ctx.String(inputFlag)
	platform = ctx.String(platformFlag)
	return
}

func tar2hashed(tarPath string, destPath string, cimOrext4 string) (string, error) {
	log.Trace("tar2hashed called")

	tarReader, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer tarReader.Close()

	entryReader, closer, err := decompressIfNeeded(tarReader)
	if err != nil {
		return "", err
	}
	if closer != nil {
		defer closer.Close()
	}

	entryReader, isTar := isTar(entryReader)
	if !isTar {
		return "", fmt.Errorf("input file is not a tar archive")
	}

	var hash string
	if cimOrext4 == "ext4" {
		opts := []tar2ext4.Option{
			tar2ext4.ConvertWhiteout,
		}

		opts = append(opts, tar2ext4.AppendDMVerity)
		out, err := os.Create(destPath)
		if err != nil {
			return "", fmt.Errorf("failed to create layer file %s: %w", destPath, err)
		}
		defer out.Close()

		log.Trace("Using tar2ext4 Convert")
		err = tar2ext4.Convert(entryReader, out, opts...)
	} else if cimOrext4 == "cim" {
		if err != nil {
			return "", err
		}
		parentLayers := make(ParentLayers, 0)
		cimOutPath := filepath.Dir(destPath)
		layerName := filepath.Base(destPath)
		log.Trace("tar2cim")
		hash, _, err = tarToCim(entryReader, parentLayers, cimOutPath, layerName)
	}
	if err != nil {
		return "", err
	}
	log.Tracef("done tar2hashed: %s", hash)
	return hash, nil
}
