package main

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
)

func parseContainerRegistryImage(imageName string, username string, password string, onLayer LayerProcessor) (layerDigests map[int]string, layerIDs map[int]string, err error) {

	layerDigests = make(map[int]string)

	ref, err := name.ParseReference(imageName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse image reference %s: %w", imageName, err)
	}

	var remoteOpts []remote.Option
	if username != "" && password != "" {

		auth := authn.Basic{
			Username: username,
			Password: password,
		}

		authConf, err := auth.Authorization()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to set remote: %w", err)
		}

		log.Debug("using basic auth")
		authOpt := remote.WithAuth(authn.FromConfig(*authConf))
		remoteOpts = append(remoteOpts, authOpt)
	}

	image, err := remote.Image(ref, remoteOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch image %q, make sure it exists: %w", imageName, err)
	}

	layers, err := image.Layers()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch image layers: %w", err)
	}

	for layerNumber, layer := range layers {
		diffID, err := layer.DiffID()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read layer diff: %w", err)
		}

		layerDigests[layerNumber] = diffID.Hex
		layerReader, err := layer.Uncompressed()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to uncompress layer %s: %w", diffID.Hex, err)
		}
		defer layerReader.Close()

		if err = onLayer(diffID.Hex, layerReader); err != nil {
			return nil, nil, err
		}
	}

	// For the remote case, use digests for both layer ID and layer digest
	return layerDigests, layerDigests, nil
}
