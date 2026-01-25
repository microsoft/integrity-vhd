package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type ImageSource any
type ImageFetcher func() (ImageSource, error)
type LayerParser func(io.Reader) (string, error)
type ImageParser func(ImageSource, LayerParser) (map[string]string, map[string]any, error)
type ManifestParser func(map[string]any) (map[int]string, map[int]string, error)

// Legacy
type LayerProcessor func(string, io.Reader) error

func parseLocalImage(imageSource ImageSource, onLayer LayerParser) (
	layerPathToHash map[string]string,
	manifestFiles map[string]any,
	err error,
) {
	imageReader, ok := imageSource.(io.Reader)
	if !ok {
		return nil, nil, errors.New("local image parser expects io.Reader")
	}

	layerPathToHash = make(map[string]string)
	manifestFiles = make(map[string]any)

	// Do a single pass of the image contents, only loading manifest files (not
	// image layers) into memory. This approach is important to keep time and
	// space complexity low when processing large images.
	imageFileReader := tar.NewReader(imageReader)
	for {
		// Load the next file
		hdr, err := imageFileReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		log.Tracef("Parsing %s", hdr.Name)

		// Some files are compressed, so wrap the reader accordingly
		entryReader, closer, err := decompressIfNeeded(imageFileReader)
		if err != nil {
			return nil, nil, err
		}
		if closer != nil {
			defer closer.Close()
		}

		// Handle layer files
		entryReader, isTar := isTar(entryReader)
		if isTar {
			log.Trace("Handled as layer")
			hash, err := onLayer(entryReader)
			if err != nil {
				return nil, nil, err
			}
			layerPathToHash[hdr.Name] = hash
			continue
		}

		// Handle manifest files
		var obj any
		if err := json.NewDecoder(entryReader).Decode(&obj); err == nil {
			log.Trace("Handled as manifest file")
			manifestFiles[hdr.Name] = obj
		}
	}

	return
}

func processLocalImage(imageReader io.Reader, onLayer LayerProcessor) (map[int]string, map[int]string, error) {
	log.Trace("processLocalImage called")
	TraceMemUsage()
	imageFileReader := tar.NewReader(imageReader)
	configs := make(map[string]any)

	// Do a single pass of the image contents, only loading config files (not
	// image layers) into memory. This approach is important to keep time and
	// space complexity low when processing large images.
	for {
		log.Trace("looping over tar contents")
		// Load the next file header
		hdr, err := imageFileReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		log.Tracef("tar hdr: %s %d", hdr.Name, hdr.Size)
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		imageFileReader, closer, err := decompressIfNeeded(imageFileReader)
		imageFileReader, isTar := isTar(imageFileReader)
		if isTar {
			log.Infof("Found layer tarball: %s", hdr.Name)
			if err != nil {
				return nil, nil, err
			}
			if err := onLayer(hdr.Name, imageFileReader); err != nil {
				return nil, nil, err
			}
			if closer != nil {
				closer.Close()
			}
		} else {
			log.Infof("Found config file: %s", hdr.Name)
			data, err := io.ReadAll(imageFileReader)
			if err != nil {
				return nil, nil, err
			}
			var obj any
			if err := json.Unmarshal(data, &obj); err != nil {
				log.Tracef("Skipping non-JSON file %s: %v", hdr.Name, err)
				continue
			}
			configs[hdr.Name] = obj
		}
	}

	layerIdxToID := make(map[int]string)
	layerIdxToPath := make(map[int]string)
	var err error

	// Different docker engine versions will either have an OCI compliant scheme
	// for describing the image, or the older legacy docker scheme.
	layerIdxToID, layerIdxToPath, err = parseOCIImage(configs)
	if err == nil {
		log.Info("OCI image format parsed successfully.")
		return layerIdxToID, layerIdxToPath, nil
	}

	layerIdxToID, layerIdxToPath, err = parseDockerImage(configs)
	if err == nil {
		log.Info("Legacy docker image format parsed successfully.")
		return layerIdxToID, layerIdxToPath, nil
	}

	// If neither format was recognized, return an error
	return nil, nil, errors.New("image format not recognized")
}

func parseImage(ctx *cli.Context, onLayer LayerProcessor) (layerDigests map[int]string, layerIDs map[int]string, err error) {
	imageName := ctx.String(inputFlag)
	tarballPath := ctx.GlobalString(tarballFlag)
	useDocker := ctx.GlobalBool(dockerFlag)

	if useDocker && tarballPath != "" {
		return nil, nil, errors.New("cannot use both docker and tarball for image source")
	}

	processLocal := func(fetcher func(string) (io.ReadCloser, error), image string) (map[int]string, map[int]string, error) {
		imageReader, err := fetcher(image)
		if err != nil {
			return nil, nil, err
		}
		defer imageReader.Close()
		return processLocalImage(imageReader, onLayer)
	}

	if tarballPath != "" {
		return processLocal(fetchImageTarball, tarballPath)
	} else if useDocker {
		return processLocal(fetchDockerImage, imageName)
	} else {
		return processContainerRegistryImage(
			imageName,
			ctx.String(usernameFlag),
			ctx.String(passwordFlag),
			onLayer,
		)
	}
}

func combineManifestParsers(parsers []ManifestParser) ManifestParser {
	return ManifestParser(func(manifests map[string]any) (map[int]string, map[int]string, error) {
		for _, parser := range parsers {
			layerIdxToID, layerIdxToPath, err := parser(manifests)
			if err == nil {
				return layerIdxToID, layerIdxToPath, nil
			}
		}
		return nil, nil, errors.New("image manifest format not recognized")
	})
}
