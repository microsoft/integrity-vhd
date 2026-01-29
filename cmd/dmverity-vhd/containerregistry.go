package main

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
)

func parsePlatform(spec string) (*v1.Platform, error) {
	log.Trace("parsePlatform called")

	parts := strings.Split(spec, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("platform %q must be in os/arch or os/arch/variant format", spec)
	}

	platform := &v1.Platform{
		OS:           strings.ToLower(strings.TrimSpace(parts[0])),
		Architecture: strings.ToLower(strings.TrimSpace(parts[1])),
	}
	if platform.OS == "" || platform.Architecture == "" {
		return nil, fmt.Errorf("platform %q must include non-empty os and arch", spec)
	}
	if len(parts) >= 3 {
		platform.Variant = strings.ToLower(strings.TrimSpace(parts[2]))
	}
	return platform, nil
}

func fetchContainerRegistryImage(
	imageName string,
	username string,
	password string,
	platform string,
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

	requestPlatform, err := parsePlatform(platform)
	if err != nil {
		return nil, fmt.Errorf("failed to set platform: %w", err)
	}
	platformOpt := remote.WithPlatform(*requestPlatform)
	remoteOpts = append(remoteOpts, platformOpt)

	image, err = remote.Image(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch image %q, make sure it exists: %w", imageName, err)
	}

	log.Tracef("done - fetchContainerRegistryImage %s", imageName)

	return
}

func parseContainerRegistryImage(imageSource ImageSource, onLayer LayerParser) (
	layerDigestToHash map[string]string,
	manifestFiles map[string]any,
	err error,
) {
	log.Trace("parseContainerRegistryImage called")
	TraceMemUsage()

	layerDigestToHash = make(map[string]string)
	manifestFiles = make(map[string]any)

	image, ok := imageSource.(v1.Image)
	if !ok {
		return nil, nil, fmt.Errorf("container registry image parser expects v1.Image, got %T", imageSource)
	}

	// Save out the manifest
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

	// Save out the config
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
		layerDigest, err := layer.Digest()
		if err != nil {
			_ = layerReader.Close()
			return nil, nil, fmt.Errorf("failed to read layer digest %d: %w", layerNumber, err)
		}
		hash, err := onLayer(layerDigest.Hex, layerReader)
		closeErr := layerReader.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to process layer %d: %w", layerNumber, err)
		}
		if closeErr != nil {
			return nil, nil, fmt.Errorf("failed to close layer %d reader: %w", layerNumber, closeErr)
		}
		layerDigestToHash[path.Join("blobs", layerDigest.Algorithm, layerDigest.Hex)] = hash
	}

	return
}
