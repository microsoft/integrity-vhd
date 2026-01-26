package main

import (
	"errors"
	"strings"

	"github.com/urfave/cli"
)

func getImageParsers(ctx *cli.Context) (
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	err error,
) {

	// Get args
	imageName := ctx.String(inputFlag)
	username := ctx.String(usernameFlag)
	password := ctx.String(passwordFlag)
	platform := ctx.String(platformFlag)
	tarballPath := ctx.GlobalString(tarballFlag)
	useDocker := ctx.GlobalBool(dockerFlag)

	// Validation
	if useDocker && tarballPath != "" {
		err = errors.New("cannot use both docker and tarball for image source")
		return
	}

	localParser := parseLocalImage
	if strings.HasPrefix(strings.ToLower(platform), "windows") {
		localParser = parseLocalImageOrdered
	}

	if tarballPath != "" {
		imageFetcher = func() (ImageSource, error) { return fetchImageTarball(tarballPath) }
		imageParser = localParser
	} else if useDocker {
		imageFetcher = func() (ImageSource, error) { return fetchDockerImage(imageName) }
		imageParser = localParser
	} else {
		imageFetcher = func() (ImageSource, error) {
			return fetchContainerRegistryImage(imageName, username, password, platform)
		}
		imageParser = parseContainerRegistryImage
	}

	manifestParser = combineManifestParsers([]ManifestParser{
		parseOCIImage,
		parseDockerImage,
	})

	return
}
