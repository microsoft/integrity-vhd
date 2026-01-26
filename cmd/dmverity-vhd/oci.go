package main

import (
	"errors"
	"fmt"
	"path"

	log "github.com/sirupsen/logrus"
)

func parseOCIImage(configs map[string]any) (layerDiffIds map[int]string, layerDigests map[int]string, err error) {
	log.Trace("parseOCIImage called")
	TraceMemUsage()

	layerDiffIds = make(map[int]string)
	layerDigests = make(map[int]string)

	configAny, ok := configs["index.json"]
	configSource := "index.json"
	if !ok {
		if manifestAny, hasManifest := configs["manifest.json"]; hasManifest {
			configAny = manifestAny
			configSource = "manifest.json"
			ok = true
		}
	}
	if !ok {
		return nil, nil, errors.New("missing index.json or manifest.json for OCI image")
	}
	var manifest ociManifest
	for {
		log.Infof("Checking %+v", configAny)

		kind, err := detectOCIKind(configAny)
		if err != nil {
			return nil, nil, err
		}

		switch kind {
		case ociKindManifest:
			log.Info("Found manifest with layers")
			manifest, err = decodeTo[ociManifest](configAny)
			if err != nil {
				return nil, nil, fmt.Errorf("%s is not a JSON object", configSource)
			}
			if manifest.Layers == nil {
				return nil, nil, errors.New("OCI manifest layers missing or invalid")
			}
			if manifest.Config.Digest == "" {
				return nil, nil, errors.New("OCI config digest missing or invalid")
			}
			goto manifestResolved
		case ociKindIndex:
			log.Info("Found OCI index, looking for manifest")
			index, err := decodeTo[ociIndex](configAny)
			if err != nil {
				return nil, nil, fmt.Errorf("%s is not a JSON object", configSource)
			}
			// TODO: this might need to search for the correct image instead of picking the first one
			if len(index.Manifests) == 0 {
				return nil, nil, errors.New("missing manifests in OCI index")
			}
			digest := index.Manifests[0].Digest
			if digest == "" {
				return nil, nil, errors.New("manifest digest missing or not a string")
			}
			algo, hex, err := splitDigest(digest)
			if err != nil {
				return nil, nil, err
			}
			blobPath := path.Join("blobs", algo, hex)
			configAny, ok = configs[blobPath]
			if !ok {
				return nil, nil, fmt.Errorf("missing referenced blob for digest %q", digest)
			}
			configSource = blobPath
			continue
		default:
			return nil, nil, errors.New("failed to parse OCI manifest")
		}
	}
manifestResolved:
	log.Infof("Using OCI manifest digest: %+v", manifest)

	layerDigestsByIndex := make(map[int]string, len(manifest.Layers))
	for i, layer := range manifest.Layers {
		log.Tracef("OCI layer[%d]: %+v", i, layer)
		if layer.Digest == "" {
			return nil, nil, errors.New("OCI layer digest missing or not a string")
		}
		_, layerDigest, err := splitDigest(layer.Digest)
		if err != nil {
			return nil, nil, err
		}
		layerDiffIds[i] = layerDigest
		layerDigestsByIndex[i] = layer.Digest
	}

	configDigest := manifest.Config.Digest
	configAlgorithm, configHex, err := splitDigest(configDigest)
	if err != nil {
		return nil, nil, err
	}
	configCandidates := configBlobCandidates(configAlgorithm, configHex)
	configBlob, err := lookupBlob(configs, configAlgorithm, configHex, configCandidates)
	if err != nil {
		return nil, nil, err
	}
	config, err := decodeTo[ociConfig](configBlob.Data)
	if err != nil {
		return nil, nil, errors.New("OCI config rootfs missing or invalid")
	}
	if config.RootFS == nil {
		return nil, nil, errors.New("OCI config rootfs missing or invalid")
	}
	if config.RootFS.DiffIDs == nil {
		return nil, nil, errors.New("OCI config diff_ids missing or invalid")
	}
	for i, diffID := range config.RootFS.DiffIDs {
		_, layerDiffID, err := splitDigest(diffID)
		if err != nil {
			return nil, nil, err
		}
		layerDiffIds[i] = layerDiffID
	}

	layerPrefix := layerPrefixFromConfigPath(configBlob.Path, configAlgorithm, configHex)

	for i, layerDigest := range layerDigestsByIndex {
		_, layerHex, err := splitDigest(layerDigest)
		if err != nil {
			return nil, nil, err
		}
		if layerPrefix == "" {
			layerDigests[i] = layerHex
		} else {
			layerDigests[i] = path.Join(layerPrefix, layerHex)
		}
	}

	return layerDiffIds, layerDigests, nil
}
