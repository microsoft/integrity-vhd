package main

import (
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func getImageParsers(ctx *cli.Context) (
	imageFetcher ImageFetcher,
	imageParser ImageParser,
	manifestParser ManifestParser,
	err error,
) {
	log.Trace("getImageParsers called")

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

	// Ensure proper image source is provided
	if tarballPath == "" && imageName == "" {
		// Only tarball works without -i flag
		err = errors.New("must provide -i/--image flag (not required only when using --tarball)")
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
		parseDockerManifests,
	})

	return
}
