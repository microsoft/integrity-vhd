package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	typesimage "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/urfave/cli"
)

type perfBudget struct {
	maxDuration    time.Duration
	maxTotalAllocB uint64
}

type TestImage struct {
	name   string
	ref    string
	budget perfBudget
	hashes []string
}

var testImages = []TestImage{
	{
		name: "cbl-mariner-core-2.0",
		ref:  "mcr.microsoft.com/cbl-mariner/base/core@sha256:537f38378c574bfa8aee6c520c3317502d9a50f5bf8e7f2bf5c30774e2c25886",
		budget: perfBudget{
			maxDuration:    3 * time.Second,
			maxTotalAllocB: 320_000_000,
		},
		hashes: []string{
			"e9846fc8d4417bad344ad0d41b6a780ff25efe77402188acfb50a13195d1378e",
			"73575a9d6e89e6b354223516a976c1c566df7497e96fe0f9ff5904fc0324dbff",
		},
	},
	{
		name: "azurelinux-core-3.0",
		ref:  "mcr.microsoft.com/azurelinux/base/core@sha256:94ad614201891509f6680b8d392f519df0274460417dfe6662643800822e380d",
		budget: perfBudget{
			maxDuration:    2 * time.Second,
			maxTotalAllocB: 360_000_000,
		},
		hashes: []string{
			"a189b02d4858578459fda1dfbd7c6a4557c44208b9829e02b931771a6d611c39",
		},
	},
	{
		name: "ubuntu-20.04",
		ref:  "mcr.microsoft.com/mirror/docker/library/ubuntu@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214",
		budget: perfBudget{
			maxDuration:    2 * time.Second,
			maxTotalAllocB: 420_000_000,
		},
		hashes: []string{
			"02fa77cb7818492438415303e3655003f38200685a4c48381350a9284ff19531",
		},
	},
	{
		name: "python-3.11-slim",
		ref:  "mcr.microsoft.com/mirror/docker/library/python@sha256:193fdd0bbcb3d2ae612bd6cc3548d2f7c78d65b549fcaa8af75624c47474444d",
		budget: perfBudget{
			maxDuration:    4 * time.Second,
			maxTotalAllocB: 650_000_000,
		},
		hashes: []string{
			"20ea848262eefa644a5b1f36906cf08dd6b3e83effcead64b5d6352313e3259e",
			"d861e75d8baaaabfcc63e45406e5fafc352dab14ebbeea2b28fd9eed01d7133c",
			"75fe145daa3a9e558083315ffa32458b41b300193d12b5ce59217826356e3fea",
			"81fba1a51fe5fbfa8eaf6b3b5e9411121517c7a4392cee16f37fe3122c277c0b",
		},
	},
	{
		name: "redis-7.2",
		ref:  "mcr.microsoft.com/mirror/docker/library/redis@sha256:5a12cb25b33b791f017419b386bb0e4e02566970fc8f23adf7f61d9291194b9c",
		budget: perfBudget{
			maxDuration:    5 * time.Second,
			maxTotalAllocB: 850_000_000,
		},
		hashes: []string{
			"a0221c80b4a61531aa3264887ac804897cbab828b1345b86c54dad260df53989",
			"3add0605006e27c91ddddce44157f013a4c7620656ee47ef77a8864adc858ea4",
			"5285b6553254d02e482b90c8466cb50ca47bb637ed5943ae36be03e854981367",
			"3695b097487dec0f2b140bc5c0aba56773d2b538e0b7fd09ee74114c893d71fc",
			"8d59ed6ef381ae2898a1363471cbee6c9b95681cc0aefa0169a651d25cda7f42",
			"c19f229c0ea3281c97ca86d9555ee2bdd98331a2fc20d33dadb6ef6c1cf09a13",
			"8b4842f06982817534a75bcf71865213b09dfa8313229c384e5201dadbd75e25",
			"4f6a05abbb5b3792d9fb09ac90d40567c871232671f44b08367f1dbf9ae20c06",
		},
	},
}

const dockerAvailabilityTimeout = 5 * time.Second

var rootHashLine = regexp.MustCompile(`^Layer ([0-9]+) root hash: ([0-9a-f]{64})$`)

func TestRootHash(t *testing.T) {
	dockerClient := requireDockerClient(t)
	for _, image := range testImages {
		t.Run(image.name, func(t *testing.T) {
			ensureDockerImage(t, dockerClient, image.ref)
			_, hashes := runRootHash(t, image.ref)
			assertExpectedHashes(t, hashes, image.hashes)
		})
	}
}

func TestRootHashPerf(t *testing.T) {
	dockerClient := requireDockerClient(t)
	for _, image := range testImages {
		t.Run(image.name, func(t *testing.T) {
			ensureDockerImage(t, dockerClient, image.ref)
			duration, totalAlloc := measureRootHash(t, image.ref)
			t.Logf("root hash duration=%s total_alloc=%d", duration, totalAlloc)
			if duration > image.budget.maxDuration {
				t.Fatalf("root hash duration %s exceeds budget %s", duration, image.budget.maxDuration)
			}
			if totalAlloc > image.budget.maxTotalAllocB {
				t.Fatalf("root hash total alloc %d exceeds budget %d", totalAlloc, image.budget.maxTotalAllocB)
			}
		})
	}
}

func runRootHash(t *testing.T, image string) (string, map[int]string) {
	t.Helper()

	ctx := buildRootHashContext(t, image)
	output, err := captureStdout(t, func() error {
		return runRootHashAction(t, ctx)
	})
	if err != nil {
		t.Fatalf("root hash failed for %s: %v", image, err)
	}

	hashes := parseRootHashOutput(t, output)
	return output, hashes
}

func measureRootHash(t *testing.T, image string) (time.Duration, uint64) {
	t.Helper()

	ctx := buildRootHashContext(t, image)
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	start := time.Now()
	if err := withStdout(devNull, func() error {
		return runRootHashAction(t, ctx)
	}); err != nil {
		t.Fatalf("root hash failed for %s: %v", image, err)
	}
	duration := time.Since(start)

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	totalAlloc := after.TotalAlloc - before.TotalAlloc
	return duration, totalAlloc
}

func buildRootHashContext(t *testing.T, image string) *cli.Context {
	t.Helper()

	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.BoolFlag{Name: dockerFlag},
		cli.StringFlag{Name: tarballFlag},
		cli.BoolFlag{Name: bufferedReaderFlag},
		cli.BoolFlag{Name: verboseFlag},
	}

	globalSet := flag.NewFlagSet("global", flag.ContinueOnError)
	globalSet.SetOutput(io.Discard)
	for _, f := range app.Flags {
		f.Apply(globalSet)
	}
	if err := globalSet.Set(dockerFlag, "true"); err != nil {
		t.Fatalf("set docker flag: %v", err)
	}

	parent := cli.NewContext(app, globalSet, nil)

	localSet := flag.NewFlagSet("roothash", flag.ContinueOnError)
	localSet.SetOutput(io.Discard)
	for _, f := range rootHashVHDCommand.Flags {
		f.Apply(localSet)
	}
	if err := localSet.Set(inputFlag, image); err != nil {
		t.Fatalf("set input flag: %v", err)
	}

	return cli.NewContext(app, localSet, parent)
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer

	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(&buf, reader)
		done <- err
	}()

	actionErr := fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	os.Stdout = originalStdout
	if err := reader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}

	return buf.String(), actionErr
}

func withStdout(writer *os.File, fn func() error) error {
	originalStdout := os.Stdout
	os.Stdout = writer
	defer func() {
		os.Stdout = originalStdout
	}()
	return fn()
}

func parseRootHashOutput(t *testing.T, output string) map[int]string {
	t.Helper()

	hashes := make(map[int]string)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		matches := rootHashLine.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}
		layerIndex, err := strconv.Atoi(matches[1])
		if err != nil {
			t.Fatalf("parse layer index %q: %v", matches[1], err)
		}
		if _, exists := hashes[layerIndex]; exists {
			t.Fatalf("duplicate layer index %d in output", layerIndex)
		}
		hashes[layerIndex] = matches[2]
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan output: %v", err)
	}
	if len(hashes) == 0 {
		t.Fatalf("no root hashes found in output:\n%s", output)
	}
	return hashes
}

func runRootHashAction(t *testing.T, ctx *cli.Context) error {
	t.Helper()

	action, ok := rootHashVHDCommand.Action.(func(*cli.Context) error)
	if !ok {
		t.Fatalf("root hash command action has unexpected type %T", rootHashVHDCommand.Action)
	}
	return action(ctx)
}

func assertExpectedHashes(t *testing.T, hashes map[int]string, expected []string) {
	t.Helper()

	if len(expected) == 0 {
		t.Fatalf("missing expected hashes")
	}
	if len(hashes) != len(expected) {
		t.Fatalf("expected %d layers, got %d", len(expected), len(hashes))
	}
	for i, expectedHash := range expected {
		actualHash, ok := hashes[i]
		if !ok {
			t.Fatalf("missing layer index %d", i)
		}
		if actualHash != expectedHash {
			t.Fatalf("layer %d root hash %s does not match expected %s", i, actualHash, expectedHash)
		}
	}
}

func dockerAvailable(t *testing.T) (*client.Client, bool) {
	t.Helper()

	cliClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), dockerAvailabilityTimeout)
	defer cancel()
	if _, err := cliClient.Ping(ctx); err != nil {
		return nil, false
	}

	return cliClient, true
}

func requireDockerClient(t *testing.T) *client.Client {
	t.Helper()

	dockerClient, ok := dockerAvailable(t)
	if !ok {
		t.Skip("docker daemon not available")
	}
	return dockerClient
}

func ensureDockerImage(t *testing.T, cliClient *client.Client, image string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if _, _, err := cliClient.ImageInspectWithRaw(ctx, image); err == nil {
		return
	}

	reader, err := cliClient.ImagePull(ctx, image, typesimage.PullOptions{})
	if err != nil {
		t.Fatalf("pull image %s: %v", image, err)
	}
	_, _ = io.Copy(io.Discard, reader)
	_ = reader.Close()
}
