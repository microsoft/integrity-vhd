package main

import (
	"context"
	"errors"
	"io"

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

func parseDockerManifests(manifests map[string]any) (layerDiffIds map[int]string, layerDigests map[int]string, err error) {
	log.Trace("parseDockerManifests called")
	TraceMemUsage()

	layerDiffIds = make(map[int]string)
	layerDigests = make(map[int]string)

	log.Tracef("manifests: %+v", manifests)
	manifestAny, ok := manifests["manifest.json"]
	if !ok {
		log.Tracef("No manifest.json found")
		return nil, nil, errors.New("not a legacy docker image")
	}

	legacyManifest, err := decodeTo[[]dockerLegacyManifest](manifestAny)
	if err != nil || len(legacyManifest) == 0 {
		return nil, nil, errors.New("manifest.json missing or invalid")
	}

	// TODO: this might need to search for the correct image instead of picking the first one
	configPath := legacyManifest[0].Config
	if configPath == "" {
		return nil, nil, errors.New("manifest config path missing or invalid")
	}
	configAny, ok := manifests[configPath]
	if !ok {
		log.Trace("Legacy config not found")
		return nil, nil, errors.New("legacy config referenced in manifest.json not found")
	}
	legacyConfig, err := decodeTo[dockerLegacyConfig](configAny)
	if err != nil || legacyConfig.RootFS == nil {
		return nil, nil, errors.New("legacy config rootfs missing or invalid")
	}
	diffIDs := legacyConfig.RootFS.DiffIDs
	if diffIDs == nil {
		return nil, nil, errors.New("legacy config diff_ids missing or invalid")
	}
	for i, diffID := range diffIDs {
		_, layerDiffID, err := splitDigest(diffID)
		if err != nil {
			return nil, nil, err
		}
		layerDiffIds[i] = layerDiffID
	}

	layers := legacyManifest[0].Layers
	if layers == nil {
		return nil, nil, errors.New("manifest layers missing or invalid")
	}
	for i, layerPath := range layers {
		layerDigests[i] = layerPath
	}

	return layerDiffIds, layerDigests, nil
}
