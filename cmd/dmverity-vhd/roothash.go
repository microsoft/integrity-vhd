package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"github.com/urfave/cli"
)

func parseRoothashArgs(ctx *cli.Context) (
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	layerParser LayerParser,
	err error,
) {

	// Get args
	imageName := ctx.String(inputFlag)
	username := ctx.String(usernameFlag)
	password := ctx.String(passwordFlag)
	tarballPath := ctx.GlobalString(tarballFlag)
	useDocker := ctx.GlobalBool(dockerFlag)

	// Validation
	if useDocker && tarballPath != "" {
		err = errors.New("cannot use both docker and tarball for image source")
		return
	}

	if tarballPath != "" {
		imageFetcher = func() (ImageSource, error) { return fetchImageTarball(tarballPath) }
		imageParser = parseLocalImage
	} else if useDocker {
		imageFetcher = func() (ImageSource, error) { return fetchDockerImage(imageName) }
		imageParser = parseLocalImage
	} else {
		imageFetcher = func() (ImageSource, error) { return fetchContainerRegistryImage(imageName, username, password) }
		imageParser = parseContainerRegistryImage
	}

	manifestParser = combineManifestParsers([]ManifestParser{
		parseOCIImage,
		parseDockerImage,
	})

	layerParser = func(layerReader io.Reader) (string, error) {
		hash, err := tar2ext4.ConvertAndComputeRootDigest(layerReader)
		if err != nil {
			return "", err
		}
		return hash, nil
	}

	return
}

func roothash(
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	layerParser LayerParser,
) error {
	image, err := imageFetcher()
	if err != nil {
		return err
	}

	layerHashes, manifestFiles, err := imageParser(image, layerParser)
	if err != nil {
		return err
	}

	_, layerIdxToPath, err := manifestParser(manifestFiles)
	if err != nil {
		return err
	}

	// Print the layer number to layer hash
	var missingLayers []int
	for layerNumber := 0; layerNumber < len(layerIdxToPath); layerNumber++ {
		hash, ok := layerHashes[layerIdxToPath[layerNumber]]
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
