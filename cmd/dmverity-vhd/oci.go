package main

import (
	"errors"
	"fmt"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
)

func parseOCIImage(configs map[string]any) (map[int]string, map[int]string, error) {
	log.Trace("parseOCIImage called")

	layerIdxToPath := make(map[int]string)
	layerIdxToID := make(map[int]string)

	const (
		ociManifestType   = "application/vnd.oci.image.manifest.v1+json"
		ociIndexType      = "application/vnd.oci.image.index.v1+json"
		dockerManifestV2  = "application/vnd.docker.distribution.manifest.v2+json"
		dockerManifestV2L = "application/vnd.docker.distribution.manifest.list.v2+json"
	)

	configAny, ok := configs["index.json"]
	configSource := "index.json"
	if !ok {
		if manifestAny, hasManifest := configs["manifest.json"]; hasManifest {
			if manifestMap, isMap := manifestAny.(map[string]any); isMap {
				configAny = manifestMap
				configSource = "manifest.json"
				ok = true
			}
		}
	}
	if !ok {
		return nil, nil, errors.New("missing index.json or manifest.json for OCI image")
	}
	config, ok := configAny.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%s is not a JSON object", configSource)
	}
	var ociManifest map[string]any
	for {
		log.Infof("Checking %+v", config)

		mediaType, ok := config["mediaType"].(string)
		if !ok {
			if _, hasLayers := config["layers"]; hasLayers {
				mediaType = ociManifestType
			} else if _, hasManifests := config["manifests"]; hasManifests {
				mediaType = ociIndexType
			} else {
				return nil, nil, errors.New("missing mediaType in OCI config")
			}
		}

		if mediaType == ociManifestType || mediaType == dockerManifestV2 {
			log.Info(("Found manifest with layers"))
			ociManifest = config
			break
		}

		if mediaType == ociIndexType || mediaType == dockerManifestV2L {
			log.Info("Found OCI index, looking for manifest")
			// TODO: this might need to search for the correct image instead of picking the first one
			manifests, ok := config["manifests"].([]any)
			if !ok || len(manifests) == 0 {
				return nil, nil, errors.New("missing manifests in OCI index")
			}
			manifest, ok := manifests[0].(map[string]any)
			if !ok {
				return nil, nil, errors.New("manifest entry is not a JSON object")
			}
			digest, ok := manifest["digest"].(string)
			if !ok {
				return nil, nil, errors.New("manifest digest missing or not a string")
			}
			configAny, ok := configs[path.Join("blobs", strings.Replace(digest, ":", "/", 1))]
			if !ok {
				return nil, nil, fmt.Errorf("missing referenced blob for digest %q", digest)
			}
			config, ok = configAny.(map[string]any)
			if !ok {
				return nil, nil, errors.New("referenced blob is not a JSON object")
			}
			continue
		}

		return nil, nil, errors.New("failed to parse OCI manifest")
	}
	log.Infof("Using OCI manifest digest: %+v", ociManifest)

	layerPathPrefix := path.Join("blobs", "sha256")
	if configAny, ok := ociManifest["config"].(map[string]any); ok {
		if digest, ok := configAny["digest"].(string); ok {
			if parts := strings.SplitN(digest, ":", 2); len(parts) == 2 {
				if _, ok := configs[parts[1]]; ok {
					layerPathPrefix = ""
				}
			}
		}
	}

	layers, ok := ociManifest["layers"].([]any)
	if !ok {
		return nil, nil, errors.New("OCI manifest layers missing or invalid")
	}
	for i, layer := range layers {
		layerMap, ok := layer.(map[string]any)
		if !ok {
			return nil, nil, errors.New("OCI layer entry is not a JSON object")
		}
		layerDigest, ok := layerMap["digest"].(string)
		if !ok {
			return nil, nil, errors.New("OCI layer digest missing or not a string")
		}
		parts := strings.SplitN(layerDigest, ":", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid layer digest %q", layerDigest)
		}
		layerID := parts[1]
		layerIdxToID[i] = layerID
		if layerPathPrefix == "" {
			layerIdxToPath[i] = layerID
		} else {
			layerIdxToPath[i] = path.Join(layerPathPrefix, layerID)
		}
	}

	return layerIdxToID, layerIdxToPath, nil
}
