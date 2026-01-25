package main

import (
	"fmt"
	"os"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"github.com/urfave/cli"
)

func parseHashLayerArgs(ctx *cli.Context) (tarPath string, err error) {
	tarPath = ctx.String(inputFlag)
	return
}

func hashLayer(tarPath string) error {
	tarReader, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer tarReader.Close()

	hash, err := tar2ext4.ConvertAndComputeRootDigest(tarReader)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", hash)
	return nil
}
