package main

import (
	"encoding/json"
	"errors"
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
	bearerToken string,
	identityToken string,
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
	authenticator, err := registryAuthenticator(username, password, bearerToken, identityToken)
	if err != nil {
		return nil, err
	}
	if authenticator != nil {
		remoteOpts = append(remoteOpts, remote.WithAuth(authenticator))
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

func validateRegistryAuth(username, password, bearerToken, identityToken string) error {
	hasUsername := username != ""
	hasPassword := password != ""
	hasBearerToken := bearerToken != ""
	hasIdentityToken := identityToken != ""

	if hasUsername != hasPassword {
		return errors.New("registry authentication must provide both username and password")
	}
	if hasBearerToken && hasIdentityToken {
		return errors.New("cannot use both bearer token and identity token registry authentication")
	}
	if (hasBearerToken || hasIdentityToken) && hasUsername {
		return errors.New("cannot use token with username/password registry authentication")
	}
	return nil
}

func registryAuthenticator(username, password, bearerToken, identityToken string) (authn.Authenticator, error) {
	if err := validateRegistryAuth(username, password, bearerToken, identityToken); err != nil {
		return nil, err
	}
	if bearerToken != "" {
		log.Debug("using bearer token auth")
		return &authn.Bearer{Token: bearerToken}, nil
	}
	if identityToken != "" {
		log.Debug("using identity token auth")
		return authn.FromConfig(authn.AuthConfig{IdentityToken: identityToken}), nil
	}
	if username != "" {
		log.Debug("using basic auth")
		return &authn.Basic{Username: username, Password: password}, nil
	}
	return nil, nil
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
		// Pass the full layer path to onLayer for consistency with tarball parsing
		layerPath := path.Join("blobs", layerDigest.Algorithm, layerDigest.Hex)
		hash, err := onLayer(layerPath, layerReader)
		closeErr := layerReader.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to process layer %d: %w", layerNumber, err)
		}
		if closeErr != nil {
			return nil, nil, fmt.Errorf("failed to close layer %d reader: %w", layerNumber, err)
		}
		layerDigestToHash[layerPath] = hash
	}

	return
}
