package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"

	log "github.com/sirupsen/logrus"
)

type ImageSource any
type ImageFetcher func() (ImageSource, error)
type LayerParser func(string, io.Reader) (string, error)
type ImageParser func(ImageSource, LayerParser) (layerDigestToHash map[string]string, manifests map[string]any, err error)
type ManifestParser func(map[string]any) (layerDiffIds map[int]string, layerDigests map[int]string, err error)

func parseLocalImage(imageSource ImageSource, onLayer LayerParser) (
	layerDigestToHash map[string]string,
	manifests map[string]any,
	err error,
) {
	log.Trace("parseLocalImage called")
	TraceMemUsage()

	imageReader, ok := imageSource.(io.Reader)
	if !ok {
		return nil, nil, errors.New("local image parser expects io.Reader")
	}

	layerDigestToHash = make(map[string]string)
	manifests = make(map[string]any)

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

		// Handle layer files
		entryReader, isTar := isTar(entryReader)
		if isTar {
			log.Trace("Handled as layer")
			hash, err := onLayer(hdr.Name, entryReader)
			if closer != nil {
				_ = closer.Close()
			}
			if err != nil {
				return nil, nil, err
			}
			layerDigestToHash[hdr.Name] = hash
			continue
		}

		// Handle manifest files
		var obj any
		if err := json.NewDecoder(entryReader).Decode(&obj); err == nil {
			log.Trace("Handled as manifest file")
			manifests[hdr.Name] = obj
		}
		if closer != nil {
			_ = closer.Close()
		}
	}

	return
}

func combineManifestParsers(parsers []ManifestParser) ManifestParser {
	log.Trace("combineManifestParsers called")

	return ManifestParser(func(manifests map[string]any) (map[int]string, map[int]string, error) {
		log.Trace("combinedManifestParser called")

		for _, parser := range parsers {
			layerDiffIDs, layerDigests, err := parser(manifests)
			if err == nil {
				return layerDiffIDs, layerDigests, nil
			} else {
				log.Tracef("Manifest parser %T failed: %v", parser, err)
			}
		}
		return nil, nil, errors.New("image manifest format not recognized")
	})
}
