package main

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func fullImageConfig(diffIDs []string, command string) map[string]any {
	return map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"config": map[string]any{
			"Entrypoint": []string{"/bin/sh"},
			"Cmd":        []string{"-c", command},
			"Env":        []string{"PATH=/bin", "MODE=selected"},
			"User":       "1000:1000",
			"WorkingDir": "/work",
			"Labels":     map[string]string{"test": command},
		},
		"rootfs":  map[string]any{"type": "layers", "diff_ids": diffIDs},
		"history": []map[string]any{{"created_by": command, "empty_layer": false}},
		"extension": map[string]any{
			"integer": json.Number("9007199254740993"),
			"nested":  []any{true, nil, "preserved"},
		},
	}
}

func assertImageConfig(t *testing.T, actual json.RawMessage, expected any) {
	t.Helper()
	want, err := encodeImageConfig(expected)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) any {
		t.Helper()
		var value any
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("invalid image config: %v: %s", err, data)
		}
		return value
	}
	if !reflect.DeepEqual(decode(actual), decode(want)) {
		t.Fatalf("config changed:\ngot  %s\nwant %s", actual, want)
	}
}

func selectedConfigFixture(t *testing.T) map[string]any {
	t.Helper()
	// Two independent archive manifests disagree deliberately. The config must
	// follow whichever parser succeeds, including OCI-to-Docker fallback.
	return map[string]any{
		"index.json": map[string]any{
			"manifests": []ociDescriptor{{Digest: "sha256:first"}, {Digest: "sha256:second"}},
		},
		"blobs/sha256/first": map[string]any{
			"config": ociDescriptor{Digest: "sha256:oci-config"},
			"layers": []ociDescriptor{{Digest: "sha256:oci-layer"}},
		},
		"blobs/sha256/second": map[string]any{
			"config": ociDescriptor{Digest: "sha256:other-config"},
			"layers": []ociDescriptor{{Digest: "sha256:other-layer"}},
		},
		"blobs/sha256/oci-config":   fullImageConfig([]string{"sha256:oci-diff"}, "oci"),
		"blobs/sha256/other-config": fullImageConfig([]string{"sha256:other-diff"}, "other"),
		"docker-config.json":        fullImageConfig([]string{"sha256:docker-diff"}, "docker"),
		"manifest.json": []dockerLegacyManifest{
			{Config: "docker-config.json", Layers: []string{"docker-layer.tar"}},
			{Config: "blobs/sha256/other-config", Layers: []string{"other-layer.tar"}},
		},
	}
}

func TestSelectedImageConfig(t *testing.T) {
	for _, name := range []string{"oci", "nested", "docker", "fallback", "docker-parser"} {
		t.Run(name, func(t *testing.T) {
			files := selectedConfigFixture(t)
			parser := combineManifestParsers([]ManifestParser{parseOCIImage, parseDockerManifests})
			configPath, layerPath, diffID := "blobs/sha256/oci-config", "blobs/sha256/oci-layer", "oci-diff"
			switch name {
			case "nested":
				files["blobs/sha256/nested"] = files["index.json"]
				files["index.json"] = map[string]any{"manifests": []ociDescriptor{{Digest: "sha256:nested"}}}
			case "docker":
				delete(files, "index.json")
			case "fallback":
				files["index.json"] = map[string]any{"manifests": []ociDescriptor{{Digest: "sha256:missing"}}}
			case "docker-parser":
				parser = parseDockerManifests
			}
			if name == "docker" || name == "fallback" || name == "docker-parser" {
				configPath, layerPath, diffID = "docker-config.json", "docker-layer.tar", "docker-diff"
			}
			diffIDs, paths, _, config, err := parser(files)
			if err != nil {
				t.Fatal(err)
			}
			if len(paths) != 1 || paths[0] != layerPath || diffIDs[0] != diffID {
				t.Fatalf("wrong selected layers: %v %v", paths, diffIDs)
			}
			assertImageConfig(t, config, files[configPath])
		})
	}
}

func TestImageConfigRepresentations(t *testing.T) {
	config := fullImageConfig([]string{"sha256:diff"}, "selected")
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, raw, json.RawMessage(raw)} {
		for _, parser := range []ManifestParser{parseOCIImage, parseDockerManifests} {
			files := selectedConfigFixture(t)
			files["blobs/sha256/oci-config"] = value
			files["docker-config.json"] = value
			_, _, _, actual, err := parser(files)
			if err != nil {
				t.Fatal(err)
			}
			assertImageConfig(t, actual, config)
		}
	}
	for _, value := range []any{nil, []byte("null"), []byte("[]"), []byte(`"string"`), []byte("{"), make(chan int)} {
		if _, err := encodeImageConfig(value); err == nil {
			t.Fatalf("accepted invalid config: %v", value)
		}
	}
}

func TestImageConfigMalformed(t *testing.T) {
	for _, format := range []string{"oci", "docker"} {
		for _, name := range []string{"missing", "null", "array", "invalid-json", "no-rootfs", "no-diffids", "invalid-digest"} {
			t.Run(format+"/"+name, func(t *testing.T) {
				files := selectedConfigFixture(t)
				parser, configPath := ManifestParser(parseOCIImage), "blobs/sha256/oci-config"
				if format == "docker" {
					parser, configPath = parseDockerManifests, "docker-config.json"
				}
				switch name {
				case "missing":
					delete(files, configPath)
				case "null":
					files[configPath] = json.RawMessage("null")
				case "array":
					files[configPath] = json.RawMessage("[]")
				case "invalid-json":
					files[configPath] = json.RawMessage("{")
				case "no-rootfs":
					files[configPath] = map[string]any{"config": map[string]any{}}
				case "no-diffids":
					files[configPath] = map[string]any{"rootfs": map[string]any{}}
				case "invalid-digest":
					files[configPath] = fullImageConfig([]string{"invalid"}, "bad")
				}
				_, _, _, config, err := parser(files)
				if err == nil || config != nil {
					t.Fatalf("malformed config must fail without output: config=%s err=%v", config, err)
				}
			})
		}
	}
}

func TestCreateVHDSelectedImageConfig(t *testing.T) {
	for _, name := range []string{"oci", "docker", "fallback", "docker-parser"} {
		t.Run(name, func(t *testing.T) {
			files := selectedConfigFixture(t)
			parser := combineManifestParsers([]ManifestParser{parseOCIImage, parseDockerManifests})
			configPath, layerPath := "blobs/sha256/oci-config", "blobs/sha256/oci-layer"
			if name != "oci" {
				configPath, layerPath = "docker-config.json", "docker-layer.tar"
			}
			switch name {
			case "docker":
				delete(files, "index.json")
			case "fallback":
				files["index.json"] = map[string]any{"manifests": []ociDescriptor{}}
			case "docker-parser":
				parser = parseDockerManifests
			}
			layerTar := createLayerTarBytes(t)
			diffID := sha256Hex(layerTar)
			files[configPath] = fullImageConfig([]string{"sha256:" + diffID}, name)
			entries := []tarEntry{{name: layerPath, data: layerTar}}
			for path, value := range files {
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				entries = append(entries, tarEntry{name: path, data: data})
			}
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeTarFile(t, tarPath, entries)
			image, err := fetchImageTarball(tarPath)
			if err != nil {
				t.Fatal(err)
			}
			defer image.Close()
			fetches := 0
			outDir := filepath.Join(t.TempDir(), "out")
			output, err := captureStdout(t, func() error {
				return createVhd(func() (ImageSource, error) {
					fetches++
					return image, nil
				}, parseLocalImage, parser, "example.com/image:mutable", outDir, "linux/amd64", false, false, true)
			})
			if err != nil {
				t.Fatal(err)
			}
			var result CreateVhdOutput
			if err := json.Unmarshal([]byte(output), &result); err != nil {
				t.Fatal(err)
			}
			assertImageConfig(t, result.ImageConfig, files[configPath])
			if fetches != 1 || len(result.Layers) != 1 || result.Layers[0].DiffID != diffID ||
				result.Layers[0].VhdPath != filepath.Join(outDir, diffID+".vhd") || result.Layers[0].VerityRootHash == "" {
				t.Fatalf("config/layer output mismatch: fetches=%d output=%s", fetches, output)
			}
		})
	}
}

func TestOrderedImageConfigPreservesNumbers(t *testing.T) {
	config := fullImageConfig([]string{"sha256:diff"}, "ordered")
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeTarFile(t, tarPath, []tarEntry{
		{name: "manifest.json", data: []byte(`[{"Config":"config.json","Layers":["layer.tar"]}]`)},
		{name: "config.json", data: configBytes},
		{name: "layer.tar", data: createLayerTarBytes(t)},
	})
	image, err := fetchImageTarball(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	_, manifests, err := parseLocalImageOrdered(image, func(_ string, reader io.Reader) (string, error) {
		_, err := io.Copy(io.Discard, reader)
		return "hash", err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, actual, err := parseDockerManifests(manifests)
	if err != nil {
		t.Fatal(err)
	}
	assertImageConfig(t, actual, config)
}

func TestCreateVHDRegistryImageConfig(t *testing.T) {
	layerTar := createLayerTarBytes(t)
	diffID := sha256Hex(layerTar)
	config := fullImageConfig([]string{"sha256:" + diffID}, "registry")
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeTarFile(t, tarPath, []tarEntry{
		{name: "manifest.json", data: []byte(`[{"Config":"config.json","Layers":["layer.tar"]}]`)},
		{name: "config.json", data: configBytes},
		{name: "layer.tar", data: layerTar},
	})
	// Supply a resolved v1.Image without contacting a registry or resolving a tag.
	image, err := tarball.ImageFromPath(tarPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	fetches := 0
	output, err := captureStdout(t, func() error {
		return createVhd(func() (ImageSource, error) {
			fetches++
			return image, nil
		}, parseContainerRegistryImage, parseOCIImage, "example.com/image:mutable",
			filepath.Join(t.TempDir(), "out"), "linux/amd64", false, false, true)
	})
	if err != nil {
		t.Fatal(err)
	}
	var result CreateVhdOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	assertImageConfig(t, result.ImageConfig, config)
	if fetches != 1 || len(result.Layers) != 1 || result.Layers[0].DiffID != diffID ||
		result.Layers[0].Digest == "" || result.Layers[0].VerityRootHash == "" {
		t.Fatalf("registry config/layers mismatch: fetches=%d output=%s", fetches, output)
	}
}

func TestCreateVHDMalformedImageConfig(t *testing.T) {
	for _, parser := range []ImageParser{parseLocalImage, parseLocalImageOrdered} {
		for _, config := range []string{`null`, `{`, `{} trailing`, `{} {}`, `{"rootfs":{"diff_ids":[]}}`} {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeTarFile(t, tarPath, []tarEntry{
				{name: "manifest.json", data: []byte(`[{"Config":"config.json","Layers":["layer.tar"]}]`)},
				{name: "config.json", data: []byte(config)},
			})
			image, err := fetchImageTarball(tarPath)
			if err != nil {
				t.Fatal(err)
			}
			defer image.Close()
			output, err := captureStdout(t, func() error {
				return createVhd(func() (ImageSource, error) { return image, nil },
					parser, parseDockerManifests, "bad:tag", t.TempDir(), "linux/amd64", false, false, true)
			})
			if err == nil || output != "" {
				t.Fatalf("malformed config emitted success: config=%s output=%s err=%v", config, output, err)
			}
		}
	}
}

func TestImageConfigLegacyOutput(t *testing.T) {
	for _, document := range []string{
		`{"schema_version":"1","image_reference":"old:tag","layers":[]}`,
		`{"schema_version":"1","image_reference":"old:tag","layers":[],"image_config":null}`,
	} {
		var output CreateVhdOutput
		if err := json.Unmarshal([]byte(document), &output); err != nil {
			t.Fatal(err)
		}
		if len(output.ImageConfig) != 0 && string(output.ImageConfig) != "null" {
			t.Fatalf("legacy output must not fabricate config: %s", output.ImageConfig)
		}
	}
}
