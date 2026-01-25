package main

import (
	"errors"
	"fmt"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
)

func parseOCIImage(configs map[string]any) (layerDiffIds map[int]string, layerDigests map[int]string, err error) {
	log.Trace("parseOCIImage called")

	layerDiffIds = make(map[int]string)
	layerDigests = make(map[int]string)

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

	layers, ok := ociManifest["layers"].([]any)
	if !ok {
		return nil, nil, errors.New("OCI manifest layers missing or invalid")
	}
	layerDigestsByIndex := make(map[int]string, len(layers))
	for i, layer := range layers {
		layerMap, ok := layer.(map[string]any)
		if !ok {
			return nil, nil, errors.New("OCI layer entry is not a JSON object")
		}
		log.Tracef("OCI layer[%d]: %+v", i, layerMap)
		layerDigest, ok := layerMap["digest"].(string)
		if !ok {
			return nil, nil, errors.New("OCI layer digest missing or not a string")
		}
		parts := strings.SplitN(layerDigest, ":", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid layer digest %q", layerDigest)
		}
		layerID := parts[1]
		layerDiffIds[i] = layerID
		layerDigestsByIndex[i] = layerDigest
	}

	config, ok = ociManifest["config"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("OCI manifest config missing or invalid")
	}
	configDigest, ok := config["digest"].(string)
	if !ok {
		return nil, nil, errors.New("OCI config digest missing or not a string")
	}
	configParts := strings.SplitN(configDigest, ":", 2)
	if len(configParts) != 2 {
		return nil, nil, fmt.Errorf("invalid config digest %q", configDigest)
	}
	configCandidates := []string{
		path.Join("blobs", configParts[0], configParts[1]),
		path.Join(configParts[0], configParts[1]),
		configParts[1],
	}
	var configFile any
	var configPath string
	for _, candidate := range configCandidates {
		if candidateConfig, ok := configs[candidate]; ok {
			configFile = candidateConfig
			configPath = candidate
			break
		}
	}
	if configFile == nil {
		return nil, nil, fmt.Errorf("missing referenced config blob for digest %q", configDigest)
	}
	rootfs, ok := configFile.(map[string]any)["rootfs"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("OCI config rootfs missing or invalid")
	}
	diffIDs, ok := rootfs["diff_ids"].([]any)
	if !ok {
		return nil, nil, errors.New("OCI config diff_ids missing or invalid")
	}
	for i, diffIDAny := range diffIDs {
		diffID, ok := diffIDAny.(string)
		if !ok {
			return nil, nil, errors.New("OCI config diff_id is not a string")
		}
		parts := strings.SplitN(diffID, ":", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid diff_id %q", diffID)
		}
		layerDiffIds[i] = parts[1]
	}

	var layerPrefix string
	switch configPath {
	case configParts[1]:
		layerPrefix = ""
	case path.Join(configParts[0], configParts[1]):
		layerPrefix = configParts[0]
	default:
		layerPrefix = path.Join("blobs", configParts[0])
	}

	for i, layerDigest := range layerDigestsByIndex {
		parts := strings.SplitN(layerDigest, ":", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid layer digest %q", layerDigest)
		}
		switch layerPrefix {
		case "":
			layerDigests[i] = parts[1]
		default:
			layerDigests[i] = path.Join(layerPrefix, parts[1])
		}
	}

	return layerDiffIds, layerDigests, nil
}
