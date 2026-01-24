package main

import (
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"
)

func parseDockerImage(configs map[string]any) (map[int]string, map[int]string, error) {
	log.Trace("parseLegacyImage called")
	layerIdxToPath := make(map[int]string)
	layerIdxToID := make(map[int]string)

	log.Tracef("configs: %+v", configs)
	legacyManifest, ok := configs["manifest.json"].([]any)
	if !ok {
		log.Tracef("No manifest.json found")
		return nil, nil, errors.New("not a legacy docker image")
	}

	// TODO: this might need to search for the correct image instead of picking the first one
	manifest := legacyManifest[0].(map[string]any)

	configPath := manifest["Config"].(string)
	legacyConfig, ok := configs[configPath].(map[string]any)
	if !ok {
		log.Trace("Legacy config not found")
		return nil, nil, errors.New("legacy config referenced in manifest.json not found")
	}

	for i, layer := range legacyConfig["rootfs"].(map[string]any)["diff_ids"].([]any) {
		layerID := strings.SplitN(layer.(string), ":", 2)[1]
		layerIdxToID[i] = layerID
	}

	for i, layer := range manifest["Layers"].([]any) {
		layerPath := layer.(string)
		layerIdxToPath[i] = layerPath
	}

	return layerIdxToID, layerIdxToPath, nil
}
