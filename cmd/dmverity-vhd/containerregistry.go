package main

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
)

func fetchContainerRegistryImage(
	imageName string,
	username string,
	password string,
) (
	image v1.Image,
	err error,
) {
	log.Tracef("fetchContainerRegistryImage called for image: %s", imageName)
	TraceMemUsage()

	ref, err := name.ParseReference(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %s: %w", imageName, err)
	}

	var remoteOpts []remote.Option
	if username != "" && password != "" {

		auth := authn.Basic{
			Username: username,
			Password: password,
		}

		authConf, err := auth.Authorization()
		if err != nil {
			return nil, fmt.Errorf("failed to set remote: %w", err)
		}

		log.Debug("using basic auth")
		authOpt := remote.WithAuth(authn.FromConfig(*authConf))
		remoteOpts = append(remoteOpts, authOpt)
	}

	image, err = remote.Image(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch image %q, make sure it exists: %w", imageName, err)
	}

	return
}

func parseContainerRegistryImage(imageSource ImageSource, onLayer LayerParser) (
	layerPathToHash map[string]string,
	manifestFiles map[string]any,
	err error,
) {
	layerPathToHash = make(map[string]string)
	manifestFiles = make(map[string]any)

	image, ok := imageSource.(v1.Image)
	if !ok {
		return nil, nil, fmt.Errorf("container registry image parser expects v1.Image, got %T", imageSource)
	}

	manifest, err := image.Manifest()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch image manifest: %w", err)
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, nil, err
	}
	var manifestJson map[string]any
	if err := json.Unmarshal(manifestBytes, &manifestJson); err != nil {
		return nil, nil, err
	}
	manifestFiles["manifest.json"] = manifestJson

	configName, err := image.ConfigName()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch image config name: %w", err)
	}
	configBytes, err := image.RawConfigFile()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch image config file: %w", err)
	}
	var configJson map[string]any
	if err := json.Unmarshal(configBytes, &configJson); err != nil {
		return nil, nil, fmt.Errorf("unable to decode image config file: %w", err)
	}
	manifestFiles[path.Join("blobs", "sha256", configName.Hex)] = configJson

	// Read the layers
	layers, err := image.Layers()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch image layers: %w", err)
	}

	for layerNumber, layer := range layers {
		layerReader, err := layer.Uncompressed()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to uncompress layer %d: %w", layerNumber, err)
		}
		defer layerReader.Close()
		layerDigest, err := layer.Digest()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read layer digest %d: %w", layerNumber, err)
		}
		hash, err := onLayer(layerDigest.Hex, layerReader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to process layer %d: %w", layerNumber, err)
		}
		layerPathToHash[path.Join("blobs", layerDigest.Algorithm, layerDigest.Hex)] = hash
	}

	return
}
