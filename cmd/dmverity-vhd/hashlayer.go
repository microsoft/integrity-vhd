package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"github.com/urfave/cli"
)

func parseHashLayerArgs(ctx *cli.Context) (tarPath string, platform string, err error) {
	tarPath = ctx.String(inputFlag)
	platform = ctx.String(platformFlag)
	return
}

func hashLayer(tarPath string, platform string) error {
	tarReader, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer tarReader.Close()

	entryReader, closer, err := decompressIfNeeded(tarReader)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}

	entryReader, isTar := isTar(entryReader)
	if !isTar {
		return fmt.Errorf("input file is not a tar archive")
	}

	var hash string
	if strings.HasPrefix(platform, "linux") {
		hash, err = tar2ext4.ConvertAndComputeRootDigest(entryReader)
	} else if strings.HasPrefix(platform, "windows") {
		cimOut, err := os.MkdirTemp("", filepath.Base(tarPath))
		if err != nil {
			return err
		}
		parentLayers := make(ParentLayers, 0)
		hash, _, err = tarToCim(entryReader, parentLayers, cimOut, filepath.Base(tarPath))
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", hash)
	return nil
}
