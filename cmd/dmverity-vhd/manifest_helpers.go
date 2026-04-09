package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
)

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
}

type ociManifest struct {
	MediaType string          `json:"mediaType"`
	Config    ociDescriptor   `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
}

type ociIndex struct {
	MediaType string          `json:"mediaType"`
	Manifests []ociDescriptor `json:"manifests"`
}

type ociRootFS struct {
	DiffIDs []string `json:"diff_ids"`
}

type ociConfig struct {
	RootFS *ociRootFS `json:"rootfs"`
}

type dockerLegacyManifest struct {
	Config string   `json:"Config"`
	Layers []string `json:"Layers"`
}

type dockerLegacyConfig struct {
	RootFS *ociRootFS `json:"rootfs"`
}

type ociKind int

const (
	ociKindUnknown ociKind = iota
	ociKindManifest
	ociKindIndex
)

func decodeTo[T any](value any) (T, error) {
	log.Trace("decodeTo called")

	var zero T
	if value == nil {
		return zero, errors.New("cannot decode <nil>")
	}

	if typed, ok := value.(T); ok {
		return typed, nil
	}

	var data []byte
	switch v := value.(type) {
	case json.RawMessage:
		data = v
	case []byte:
		data = v
	default:
		var err error
		data, err = json.Marshal(value)
		if err != nil {
			return zero, err
		}
	}

	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return zero, err
	}
	return out, nil
}

func detectOCIKind(value any) (ociKind, error) {
	log.Trace("detectOCIKind called")

	mediaType, ok := getStringField(value, "mediaType")
	if !ok {
		switch {
		case hasField(value, "layers"):
			return ociKindManifest, nil
		case hasField(value, "manifests"):
			return ociKindIndex, nil
		default:
			return ociKindUnknown, errors.New("missing mediaType in OCI config")
		}
	}

	switch mediaType {
	case "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
		return ociKindManifest, nil
	case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json":
		return ociKindIndex, nil
	default:
		return ociKindUnknown, errors.New("failed to parse OCI manifest")
	}
}

func getStringField(value any, field string) (string, bool) {
	log.Trace("getStringField called")

	obj, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	str, ok := obj[field].(string)
	return str, ok
}

func hasField(value any, field string) bool {
	log.Trace("hasField called")

	obj, ok := value.(map[string]any)
	if !ok {
		return false
	}
	_, ok = obj[field]
	return ok
}

type blobLookup struct {
	Data      any
	Path      string
	Algorithm string
	Hex       string
}

func lookupBlob(configs map[string]any, algorithm, hex string, candidates []string) (blobLookup, error) {
	log.Trace("lookupBlob called")

	for _, candidate := range candidates {
		if candidateConfig, ok := configs[candidate]; ok {
			return blobLookup{
				Data:      candidateConfig,
				Path:      candidate,
				Algorithm: algorithm,
				Hex:       hex,
			}, nil
		}
	}
	return blobLookup{}, fmt.Errorf("missing referenced blob for digest %s:%s", algorithm, hex)
}

func configBlobCandidates(algorithm, hex string) []string {
	log.Trace("configBlobCandidates called")

	return []string{
		path.Join("blobs", algorithm, hex),
		path.Join(algorithm, hex),
		hex,
	}
}

func layerPrefixFromConfigPath(configPath, algorithm, hex string) string {
	log.Trace("layerPrefixFromConfigPath called")

	switch configPath {
	case hex:
		return ""
	case path.Join(algorithm, hex):
		return algorithm
	default:
		return path.Join("blobs", algorithm)
	}
}

func splitDigest(digest string) (string, string, error) {
	log.Trace("splitDigest called")

	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid digest %q", digest)
	}
	return parts[0], parts[1], nil
}
