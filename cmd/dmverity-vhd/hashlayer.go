package main

import (
	"fmt"
	"os"
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

	var hash string
	if strings.HasPrefix(platform, "linux") {
		hash, err = tar2ext4.ConvertAndComputeRootDigest(tarReader)
	} else if strings.HasPrefix(platform, "windows") {
		var cimOut string
		cimOut, err = os.MkdirTemp("", "layer")
		parentLayers := make(ParentLayers, 0)
		hash, _, err = tarToCim(tarReader, parentLayers, cimOut, "layer")
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", hash)
	return nil
}
