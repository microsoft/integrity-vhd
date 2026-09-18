package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestManifestLayerDigests(t *testing.T) {
	for _, prefix := range []string{"blobs/sha256", "sha256", ""} {
		t.Run("oci/"+prefix, func(t *testing.T) {
			configHex := strings.Repeat("c", 64)
			layerHex := strings.Repeat("a", 64)
			diffHex := strings.Repeat("b", 64)
			manifests := map[string]any{
				"manifest.json": map[string]any{
					"mediaType": "application/vnd.oci.image.manifest.v1+json",
					"config":    ociDescriptor{Digest: "sha256:" + configHex},
					"layers":    []ociDescriptor{{Digest: "sha256:" + layerHex}},
				},
				path.Join(prefix, configHex): ociConfig{
					RootFS: &ociRootFS{DiffIDs: []string{"sha256:" + diffHex}},
				},
			}
			parser := combineManifestParsers([]ManifestParser{parseOCIImage, parseDockerManifests})
			diffIDs, paths, digests, err := parser(manifests)
			if err != nil {
				t.Fatal(err)
			}
			if diffIDs[0] != diffHex || paths[0] != path.Join(prefix, layerHex) ||
				digests[0] != "sha256:"+layerHex {
				t.Fatalf("unexpected layer metadata: diffIDs=%v paths=%v digests=%v", diffIDs, paths, digests)
			}
		})
	}
	t.Run("docker", func(t *testing.T) {
		manifests := map[string]any{
			"manifest.json": []dockerLegacyManifest{{Config: "config.json", Layers: []string{"layer.tar"}}},
			"config.json":   dockerLegacyConfig{RootFS: &ociRootFS{DiffIDs: []string{"sha256:" + strings.Repeat("a", 64)}}},
		}
		parser := combineManifestParsers([]ManifestParser{parseOCIImage, parseDockerManifests})
		diffIDs, paths, digests, err := parser(manifests)
		if err != nil {
			t.Fatal(err)
		}
		if diffIDs[0] != strings.Repeat("a", 64) || paths[0] != "layer.tar" || digests[0] != "" {
			t.Fatalf("unexpected Docker metadata: diffIDs=%v paths=%v digests=%v", diffIDs, paths, digests)
		}
	})
}

func TestManifestLayerDigestAlgorithm(t *testing.T) {
	configHex := strings.Repeat("c", 64)
	layerHex := strings.Repeat("a", 128)
	manifests := map[string]any{
		"manifest.json": map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"config":    ociDescriptor{Digest: "sha256:" + configHex},
			"layers":    []ociDescriptor{{Digest: "sha512:" + layerHex}},
		},
		"blobs/sha256/" + configHex: ociConfig{
			RootFS: &ociRootFS{DiffIDs: []string{"sha256:" + strings.Repeat("b", 64)}},
		},
	}
	_, _, digests, err := parseOCIImage(manifests)
	if err != nil {
		t.Fatal(err)
	}
	if digests[0] != "sha512:"+layerHex {
		t.Fatalf("descriptor digest lost its algorithm: %q", digests[0])
	}
}

func TestRootHashManifestPaths(t *testing.T) {
	const configHex = "config"
	paths := []string{"blobs/sha256/base", "blobs/sha256/top"}
	manifests := map[string]any{
		"manifest.json": map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"config":    ociDescriptor{Digest: "sha256:" + configHex},
			"layers":    []ociDescriptor{{Digest: "sha256:base"}, {Digest: "sha256:top"}},
		},
		"blobs/sha256/" + configHex: ociConfig{
			RootFS: &ociRootFS{DiffIDs: []string{"sha256:base-diff", "sha256:top-diff"}},
		},
	}
	output, err := captureStdout(t, func() error {
		return roothash(
			func() (ImageSource, error) { return nil, nil },
			func(_ ImageSource, _ LayerParser) (map[string]string, map[string]any, error) {
				return map[string]string{paths[0]: "base-root", paths[1]: "top-root"}, manifests, nil
			},
			parseOCIImage, nil, nil, func() {}, "linux/amd64")
	})
	if err != nil {
		t.Fatal(err)
	}
	var result RootHashOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Layers, []string{"base-root", "top-root"}) {
		t.Fatalf("root hash lookup/order changed: %v", result.Layers)
	}
}

func TestOrderedImageManifestPaths(t *testing.T) {
	for _, format := range []string{"oci", "docker"} {
		t.Run(format, func(t *testing.T) {
			var manifests map[string]any
			paths := []string{"blobs/sha256/base", "blobs/sha256/top"}
			config := ociConfig{RootFS: &ociRootFS{DiffIDs: []string{"sha256:base-diff", "sha256:top-diff"}}}
			if format == "oci" {
				manifests = map[string]any{
					"manifest.json": ociManifest{
						MediaType: "application/vnd.oci.image.manifest.v1+json",
						Config:    ociDescriptor{Digest: "sha256:config"},
						Layers:    []ociDescriptor{{Digest: "sha256:base"}, {Digest: "sha256:top"}},
					},
					"blobs/sha256/config": config,
				}
			} else {
				paths = []string{"base/layer.tar", "top/layer.tar"}
				manifests = map[string]any{
					"manifest.json": []dockerLegacyManifest{{Config: "config.json", Layers: paths}},
					"config.json":   config,
				}
			}
			layerTar := createLayerTarBytes(t)
			entries := []tarEntry{{name: paths[1], data: layerTar}, {name: paths[0], data: layerTar}}
			for name, manifest := range manifests {
				data, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				entries = append(entries, tarEntry{name: name, data: data})
			}
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeTarFile(t, tarPath, entries)
			image, err := fetchImageTarball(tarPath)
			if err != nil {
				t.Fatal(err)
			}
			defer image.Close()
			var observed []string
			hashes, _, err := parseLocalImageOrdered(image, func(layerPath string, reader io.Reader) (string, error) {
				observed = append(observed, layerPath)
				if _, err := io.Copy(io.Discard, reader); err != nil {
					return "", err
				}
				return fmt.Sprintf("root-%d", len(observed)), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(observed, paths) || hashes[paths[0]] != "root-1" || hashes[paths[1]] != "root-2" {
				t.Fatalf("ordered layer paths/hash keys changed: paths=%v hashes=%v", observed, hashes)
			}
		})
	}
}
