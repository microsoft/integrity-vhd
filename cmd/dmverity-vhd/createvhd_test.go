package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli"
)

type createVHDContextOptions struct {
	input         string
	outputDir     string
	tarballPath   string
	useDocker     bool
	dataVhd       bool
	hashDeviceVhd bool
}

func TestCreateVHDDirectoryTarball(t *testing.T) {
	rootDir := t.TempDir()
	tarPath := filepath.Join(rootDir, "rootfs.tar")
	writeTarFile(t, tarPath, []tarEntry{{name: "hello.txt", data: []byte("hi")}})

	outDir := filepath.Join(t.TempDir(), "out")
	output, err := runCreateVHD(t, createVHDContextOptions{
		input:     tarPath,
		outputDir: outDir,
		dataVhd:   true,
	})
	if err != nil {
		t.Fatalf("create VHD failed: %v", err)
	}

	if info, err := os.Stat(outDir); err != nil || !info.IsDir() {
		t.Fatalf("output directory %s was not created", outDir)
	}

	sanitisedName := sanitiseVHDFilename(tarPath)
	expectedPath := filepath.Join(outDir, sanitisedName+".vhd")
	if _, err := os.Stat(expectedPath); err != nil {
		t.Fatalf("expected directory VHD %s to exist: %v", expectedPath, err)
	}

	expectedLine := fmt.Sprintf("Directory VHD created at %s", expectedPath)
	if !strings.Contains(output, expectedLine) {
		t.Fatalf("expected output to contain %q, got %q", expectedLine, output)
	}
}

func TestCreateVHDDirectoryTarballHashDevice(t *testing.T) {
	rootDir := t.TempDir()
	tarPath := filepath.Join(rootDir, "rootfs.tar")
	writeTarFile(t, tarPath, []tarEntry{{name: "hello.txt", data: []byte("hi")}})

	outDir := filepath.Join(t.TempDir(), "out")
	output, err := runCreateVHD(t, createVHDContextOptions{
		input:         tarPath,
		outputDir:     outDir,
		dataVhd:       true,
		hashDeviceVhd: true,
	})
	if err != nil {
		t.Fatalf("create VHD with hash device failed: %v", err)
	}

	sanitisedName := sanitiseVHDFilename(tarPath)
	hashDevicePath := filepath.Join(outDir, sanitisedName+".hash-dev.vhd")
	if _, err := os.Stat(hashDevicePath); err != nil {
		t.Fatalf("expected hash device VHD %s to exist: %v", hashDevicePath, err)
	}

	expectedLine := fmt.Sprintf("hash device created at %s", hashDevicePath)
	if !strings.Contains(output, expectedLine) {
		t.Fatalf("expected output to contain %q, got %q", expectedLine, output)
	}
}

func TestCreateVHDTarballImage(t *testing.T) {
	layerName := "layer.tar"
	layerTar := createLayerTarBytes(t)
	layerDiffID := sha256Hex(layerTar)

	imageTarPath := filepath.Join(t.TempDir(), "image.tar")
	manifest := []map[string]any{{
		"Config": "config.json",
		"Layers": []string{layerName},
	}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	config := map[string]any{
		"rootfs": map[string]any{
			"diff_ids": []string{"sha256:" + layerDiffID},
		},
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	writeTarFile(t, imageTarPath, []tarEntry{
		{name: layerName, data: layerTar},
		{name: "config.json", data: configBytes},
		{name: "manifest.json", data: manifestBytes},
	})

	outDir := filepath.Join(t.TempDir(), "out")
	output, err := runCreateVHD(t, createVHDContextOptions{
		input:       "unused",
		outputDir:   outDir,
		tarballPath: imageTarPath,
	})
	if err != nil {
		t.Fatalf("create VHD from image tarball failed: %v", err)
	}

	expectedPath := filepath.Join(outDir, layerDiffID+".vhd")
	if _, err := os.Stat(expectedPath); err != nil {
		t.Fatalf("expected layer VHD %s to exist: %v", expectedPath, err)
	}

	expectedLine := fmt.Sprintf("Layer VHD created at %s", expectedPath)
	if !strings.Contains(output, expectedLine) {
		t.Fatalf("expected output to contain %q, got %q", expectedLine, output)
	}

	tempLayerPath := filepath.Join(os.TempDir(), sanitiseVHDFilename(layerName)+".vhd")
	if _, err := os.Stat(tempLayerPath); err == nil {
		t.Fatalf("expected temporary layer VHD %s to be moved", tempLayerPath)
	}
}

func runCreateVHD(t *testing.T, opts createVHDContextOptions) (string, error) {
	t.Helper()

	ctx := buildCreateVHDContext(t, opts)
	return captureStdout(t, func() error {
		return runCreateVHDAction(t, ctx)
	})
}

func runCreateVHDAction(t *testing.T, ctx *cli.Context) error {
	t.Helper()

	action, ok := createVHDCommand.Action.(func(*cli.Context) error)
	if !ok {
		t.Fatalf("create command action has unexpected type %T", createVHDCommand.Action)
	}
	return action(ctx)
}

func buildCreateVHDContext(t *testing.T, opts createVHDContextOptions) *cli.Context {
	t.Helper()

	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.BoolFlag{Name: verboseFlag},
		cli.BoolFlag{Name: traceFlag},
		cli.BoolFlag{Name: dockerFlag},
		cli.StringFlag{Name: tarballFlag},
		cli.BoolFlag{Name: bufferedReaderFlag},
	}

	globalSet := flag.NewFlagSet("global", flag.ContinueOnError)
	globalSet.SetOutput(io.Discard)
	for _, f := range app.Flags {
		f.Apply(globalSet)
	}
	if opts.useDocker {
		if err := globalSet.Set(dockerFlag, "true"); err != nil {
			t.Fatalf("set docker flag: %v", err)
		}
	}
	if opts.tarballPath != "" {
		if err := globalSet.Set(tarballFlag, opts.tarballPath); err != nil {
			t.Fatalf("set tarball flag: %v", err)
		}
	}

	parent := cli.NewContext(app, globalSet, nil)

	localSet := flag.NewFlagSet("create", flag.ContinueOnError)
	localSet.SetOutput(io.Discard)
	for _, f := range createVHDCommand.Flags {
		f.Apply(localSet)
	}
	if err := localSet.Set(inputFlag, opts.input); err != nil {
		t.Fatalf("set input flag: %v", err)
	}
	if err := localSet.Set(outputDirFlag, opts.outputDir); err != nil {
		t.Fatalf("set output flag: %v", err)
	}
	if opts.dataVhd {
		if err := localSet.Set(dataVhdFlag, "true"); err != nil {
			t.Fatalf("set data VHD flag: %v", err)
		}
	}
	if opts.hashDeviceVhd {
		if err := localSet.Set(hashDeviceVhdFlag, "true"); err != nil {
			t.Fatalf("set hash device flag: %v", err)
		}
	}

	return cli.NewContext(app, localSet, parent)
}

type tarEntry struct {
	name string
	data []byte
}

func writeTarFile(t *testing.T, tarPath string, entries []tarEntry) {
	t.Helper()

	out, err := os.Create(tarPath)
	if err != nil {
		t.Fatalf("create tarball %s: %v", tarPath, err)
	}

	tw := tar.NewWriter(out)
	for _, entry := range entries {
		hdr := &tar.Header{
			Name: entry.name,
			Mode: 0644,
			Size: int64(len(entry.data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = out.Close()
			t.Fatalf("write tar header for %s: %v", entry.name, err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			_ = tw.Close()
			_ = out.Close()
			t.Fatalf("write tar entry %s: %v", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		_ = out.Close()
		t.Fatalf("close tar writer %s: %v", tarPath, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close tarball %s: %v", tarPath, err)
	}
}

func createLayerTarBytes(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	data := []byte("layer-content")
	hdr := &tar.Header{
		Name: "layer.txt",
		Mode: 0644,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write layer header: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("write layer data: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer tar: %v", err)
	}
	return buf.Bytes()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
