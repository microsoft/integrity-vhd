package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

func fetchDockerImage(imageName string) (imageReader io.ReadCloser, err error) {
	log.Tracef("fetchDockerImage called for image: %s", imageName)
	TraceMemUsage()

	dockerCtx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	imageReader, err = cli.ImageSave(dockerCtx, []string{imageName})
	if err != nil {
		return nil, err
	}

	return imageReader, err
}

func parseDockerImage(configs map[string]any) (layerDiffIds map[int]string, layerDigests map[int]string, err error) {
	log.Trace("parseDockerImage called")
	layerDiffIds = make(map[int]string)
	layerDigests = make(map[int]string)

	log.Tracef("configs: %+v", configs)
	manifestAny, ok := configs["manifest.json"]
	if !ok {
		log.Tracef("No manifest.json found")
		return nil, nil, errors.New("not a legacy docker image")
	}

	legacyManifest, ok := manifestAny.([]any)
	if !ok || len(legacyManifest) == 0 {
		return nil, nil, errors.New("manifest.json missing or invalid")
	}

	// TODO: this might need to search for the correct image instead of picking the first one
	manifest, ok := legacyManifest[0].(map[string]any)
	if !ok {
		return nil, nil, errors.New("manifest entry is not a JSON object")
	}

	configPath, ok := manifest["Config"].(string)
	if !ok {
		return nil, nil, errors.New("manifest config path missing or invalid")
	}
	configAny, ok := configs[configPath]
	if !ok {
		log.Trace("Legacy config not found")
		return nil, nil, errors.New("legacy config referenced in manifest.json not found")
	}
	legacyConfig, ok := configAny.(map[string]any)
	if !ok {
		return nil, nil, errors.New("legacy config is not a JSON object")
	}

	rootfs, ok := legacyConfig["rootfs"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("legacy config rootfs missing or invalid")
	}
	diffIDs, ok := rootfs["diff_ids"].([]any)
	if !ok {
		return nil, nil, errors.New("legacy config diff_ids missing or invalid")
	}
	for i, diffIDAny := range diffIDs {
		diffID, ok := diffIDAny.(string)
		if !ok {
			return nil, nil, errors.New("legacy config diff_id is not a string")
		}
		parts := strings.SplitN(diffID, ":", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid legacy diff_id %q", diffID)
		}
		layerDiffIds[i] = parts[1]
	}

	layersAny, ok := manifest["Layers"].([]any)
	if !ok {
		return nil, nil, errors.New("manifest layers missing or invalid")
	}
	for i, layerAny := range layersAny {
		layerPath, ok := layerAny.(string)
		if !ok {
			return nil, nil, errors.New("manifest layer entry is not a string")
		}
		layerDigests[i] = layerPath
	}

	return layerDiffIds, layerDigests, nil
}
