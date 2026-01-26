package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
)

// This function exists to support windows where the layers must be hashed in order.
// It comes at the expense of copying layers around to avoid holding them in memory.
func parseLocalImageOrdered(imageSource ImageSource, onLayer LayerParser) (
	layerDigestToHash map[string]string,
	manifests map[string]any,
	err error,
) {
	log.Trace("parseLocalImageOrdered called")
	TraceMemUsage()

	imageReader, ok := imageSource.(io.Reader)
	if !ok {
		return nil, nil, errors.New("local image parser expects io.Reader")
	}

	layerDigestToHash = make(map[string]string)
	manifests = make(map[string]any)
	layerFiles := make(map[string]string)

	tempDir, err := os.MkdirTemp("", "dmverity-vhd-layers")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tempDir)

	imageFileReader := tar.NewReader(imageReader)
	for {
		hdr, err := imageFileReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		entryReader, closer, err := decompressIfNeeded(imageFileReader)
		if err != nil {
			return nil, nil, err
		}
		entryReader, isLayerTar := isTar(entryReader)
		if isLayerTar {
			file, err := os.CreateTemp(tempDir, "layer-*.tar")
			if err != nil {
				if closer != nil {
					_ = closer.Close()
				}
				return nil, nil, err
			}
			_, copyErr := io.Copy(file, entryReader)
			closeErr := file.Close()
			if closer != nil {
				_ = closer.Close()
			}
			if copyErr != nil {
				return nil, nil, copyErr
			}
			if closeErr != nil {
				return nil, nil, closeErr
			}
			layerFiles[hdr.Name] = file.Name()
			continue
		}

		data, err := io.ReadAll(entryReader)
		if closer != nil {
			_ = closer.Close()
		}
		if err != nil {
			return nil, nil, err
		}
		var obj any
		if err := json.Unmarshal(data, &obj); err == nil {
			manifests[hdr.Name] = obj
		}
	}

	parseManifests := combineManifestParsers([]ManifestParser{
		parseOCIImage,
		parseDockerManifests,
	})
	_, layerDigests, err := parseManifests(manifests)
	if err != nil {
		return nil, nil, err
	}

	for layerNumber := 0; layerNumber < len(layerDigests); layerNumber++ {
		layerDigest, ok := layerDigests[layerNumber]
		if !ok {
			return nil, nil, fmt.Errorf("missing layer %d in manifest", layerNumber)
		}
		filePath, ok := layerFiles[layerDigest]
		if !ok {
			return nil, nil, fmt.Errorf("layer file %s missing", layerDigest)
		}

		file, err := os.Open(filePath)
		if err != nil {
			return nil, nil, err
		}
		reader, closer, err := decompressIfNeeded(file)
		if err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		hash, err := onLayer(layerDigest, reader)
		if closer != nil {
			_ = closer.Close()
		}
		closeErr := file.Close()
		if err != nil {
			return nil, nil, err
		}
		if closeErr != nil {
			return nil, nil, closeErr
		}
		layerDigestToHash[layerDigest] = hash
	}

	return layerDigestToHash, manifests, nil
}
