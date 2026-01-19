package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/ext4/dmverity"
	"github.com/Microsoft/hcsshim/ext4/tar2ext4"

	"compress/gzip"
)

// decompressIfNeeded wraps the reader with a gzip reader when needed.
func decompressIfNeeded(reader io.Reader) (io.Reader, io.Closer, error) {
	buffered := bufio.NewReader(reader)
	header, err := buffered.Peek(2)
	if err != nil && err != io.EOF {
		return nil, nil, err
	}
	if len(header) == 2 && header[0] == 0x1f && header[1] == 0x8b {
		gzipReader, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, nil, err
		}
		return gzipReader, gzipReader, nil
	}
	return buffered, nil, nil
}

func TraceMemUsage() {
	if log.IsLevelEnabled(log.TraceLevel) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Tracef("Alloc = %v TotalAlloc = %v Sys = %v NumGC = %v", m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
	}
}

func TraceMemUsageDesc(desc string) {
	if log.IsLevelEnabled(log.TraceLevel) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Tracef("%s: Alloc = %v TotalAlloc = %v Sys = %v NumGC = %v", desc, m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
	}
}

const usage = `dmverity-vhd is a command line tool for creating LCOW layer VHDs with dm-verity hashes.`

const (
	usernameFlag       = "username"
	passwordFlag       = "password"
	platformFlag       = "platform"
	inputFlag          = "input"
	verboseFlag        = "verbose"
	traceFlag          = "trace"
	outputDirFlag      = "out-dir"
	dockerFlag         = "docker"
	bufferedReaderFlag = "buffered-reader"
	tarballFlag        = "tarball"
	hashDeviceVhdFlag  = "hash-dev-vhd"
	dataVhdFlag        = "data-vhd"
	maxVHDSize         = dmverity.RecommendedVHDSizeGB
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
	})

	log.SetOutput(os.Stdout)

	log.SetLevel(log.WarnLevel)
	log.Info("Init ran")
	log.Trace("Init ran trace")
}

func main() {
	log.Trace("main")
	cli.VersionFlag = cli.BoolFlag{
		Name: "version",
	}

	app := cli.NewApp()
	app.Name = "dmverity-vhd"
	app.Commands = []cli.Command{
		createVHDCommand,
		rootHashVHDCommand,
	}
	app.Usage = usage
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  verboseFlag + ",v",
			Usage: "Optional: verbose output",
		},
		cli.BoolFlag{
			Name:  traceFlag + ",vv",
			Usage: "Optional: trace output",
		},
		cli.BoolFlag{
			Name:  dockerFlag + ",d",
			Usage: "Optional: use local docker daemon",
		},
		cli.StringFlag{
			Name:  tarballFlag + ",t",
			Usage: "Optional: path to tarball containing image info",
		},
		cli.BoolFlag{
			Name:  bufferedReaderFlag + ",b",
			Usage: "Optional: use buffered opener for image",
		},
	}

	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type LayerProcessor func(string, io.Reader) error

func fetchImageTarball(tarballPath string) (imageReader io.ReadCloser, err error) {
	log.Tracef("fetchImageTarball called for tarball: %s", tarballPath)
	TraceMemUsage()

	if imageReader, err = os.Open(tarballPath); err != nil {
		return nil, err
	}

	return imageReader, err
}

func fetchImageDocker(imageName string) (imageReader io.ReadCloser, err error) {
	log.Tracef("fetchImageDocker called for image: %s", imageName)
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

func isTar(reader io.Reader) (io.Reader, bool) {

	// Wraps reader in :
	//   A TeeReader which copies read bytes into a separate buffer.
	//   A TarReader to read the header of the tar file.
	var header bytes.Buffer
	teeReader := io.TeeReader(reader, &header)
	tarReader := tar.NewReader(teeReader)

	_, err := tarReader.Next()

	return io.MultiReader(&header, reader), err == nil || err == io.EOF
}

type OCIIndex struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Manifests     []struct {
		MediaType   string            `json:"mediaType"`
		Digest      string            `json:"digest"`
		Size        int64             `json:"size"`
		Annotations map[string]string `json:"annotations"`
	} `json:"manifests"`
}

type OCIManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"layers"`
}

type LegacyManifest []struct {
	Config       string   `json:"Config"`
	RepoTags     []string `json:"RepoTags"`
	Layers       []string `json:"Layers"`
	LayerSources map[string]struct {
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
	} `json:"LayerSources"`
}

type LegacyConfig struct {
	Architecture string `json:"architecture"`
	Config       struct {
		User   string            `json:"User"`
		Env    []string          `json:"Env"`
		Cmd    []string          `json:"Cmd"`
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
	Created string `json:"created"`
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		Comment    string `json:"comment"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
	OS     string `json:"os"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

func parseConfig[T any](data []byte) (any, bool) {
	var config T
	tName := reflect.TypeOf((*T)(nil)).Elem().String()
	log.Tracef("parseConfig[%s] called", tName)
	TraceMemUsage()
	decoder := json.NewDecoder(bytes.NewReader(data))
	if tName != "main.LegacyConfig" { // LegacyConfig is lenient
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(&config); err != nil {
		return nil, false
	}
	log.Infof("Parsed config as type %s: %+v", tName, config)
	return config, true
}

func parseOCIImage(configs map[string]any) (map[int]string, map[int]string, error) {
	log.Trace("parseOCIImage called")

	layerIdxToPath := make(map[int]string)
	layerIdxToID := make(map[int]string)

	ociIndex, ok := configs["index.json"].(OCIIndex)
	if !ok {
		return nil, nil, errors.New("not an OCI image")
	}
	log.Info("OCI image format detected.")

	var ociManifest OCIManifest
	for {
		// TODO: this might need to search for the correct image instead of picking the first one
		manifest := ociIndex.Manifests[0]
		config, ok := configs[path.Join("blobs", strings.Replace(manifest.Digest, ":", "/", 1))]
		if !ok {
			return nil, nil, errors.New("OCI manifest referenced in index.json not found")
		}

		nextIndex, ok := config.(OCIIndex)
		if ok {
			ociIndex = nextIndex
			continue
		}

		ociManifest, ok = config.(OCIManifest)
		if ok {
			break
		}
	}
	log.Infof("Using OCI manifest digest: %+v", ociManifest)

	for i, layer := range ociManifest.Layers {
		layerID := strings.SplitN(layer.Digest, ":", 2)[1]
		layerIdxToID[i] = layerID
		layerIdxToPath[i] = path.Join("blobs", "sha256", layerID)
	}

	return layerIdxToID, layerIdxToPath, nil
}

func parseLegacyImage(configs map[string]any) (map[int]string, map[int]string, error) {
	log.Trace("parseLegacyImage called")
	layerIdxToPath := make(map[int]string)
	layerIdxToID := make(map[int]string)

	legacyManifest, ok := configs["manifest.json"].(LegacyManifest)
	if !ok {
		return nil, nil, errors.New("not a legacy docker image")
	}

	// TODO: this might need to search for the correct image instead of picking the first one
	manifest := legacyManifest[0]

	configPath := manifest.Config
	legacyConfig, ok := configs[configPath].(LegacyConfig)
	if !ok {
		return nil, nil, errors.New("legacy config referenced in manifest.json not found")
	}

	for i, layer := range legacyConfig.RootFS.DiffIDs {
		layerID := strings.SplitN(layer, ":", 2)[1]
		layerIdxToID[i] = layerID
		layerIdxToPath[i] = path.Join("blobs", "sha256", layerID)
	}

	return layerIdxToID, layerIdxToPath, nil
}

func processLocalImage(imageReader io.Reader, onLayer LayerProcessor) (map[int]string, map[int]string, error) {
	log.Trace("processLocalImage called")
	TraceMemUsage()
	imageFileReader := tar.NewReader(imageReader)
	configs := make(map[string]any)

	// Do a single pass of the image contents, only loading config files (not
	// image layers) into memory. This approach is important to keep time and
	// space complexity low when processing large images.
	for {
		log.Trace("looping over tar contents")
		// Load the next file header
		hdr, err := imageFileReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		log.Tracef("tar hdr: %s %d", hdr.Name, hdr.Size)
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		imageFileReader, isTar := isTar(imageFileReader)
		if isTar {
			log.Infof("Found layer tarball: %s", hdr.Name)
			reader, closer, err := decompressIfNeeded(imageFileReader)
			if err != nil {
				return nil, nil, err
			}
			if err := onLayer(hdr.Name, reader); err != nil {
				return nil, nil, err
			}
			if closer != nil {
				closer.Close()
			}
		} else {
			log.Infof("Found config file: %s", hdr.Name)
			data, err := io.ReadAll(imageFileReader)
			if err != nil {
				return nil, nil, err
			}
			for _, parser := range []func([]byte) (any, bool){
				parseConfig[OCIIndex],
				parseConfig[OCIManifest],
				parseConfig[LegacyManifest],
				parseConfig[LegacyConfig],
			} {
				config, ok := parser(data)
				if ok {
					configs[hdr.Name] = config
					break
				}
			}
		}
	}

	layerIdxToID := make(map[int]string)
	layerIdxToPath := make(map[int]string)
	var err error

	// Different docker engine versions will either have an OCI compliant scheme
	// for describing the image, or the older legacy docker scheme.
	layerIdxToID, layerIdxToPath, err = parseOCIImage(configs)
	if err == nil {
		log.Info("OCI image format parsed successfully.")
		return layerIdxToID, layerIdxToPath, nil
	}

	layerIdxToID, layerIdxToPath, err = parseLegacyImage(configs)
	if err == nil {
		log.Info("Legacy docker image format parsed successfully.")
		return layerIdxToID, layerIdxToPath, nil
	}

	// If neither format was recognized, return an error
	return nil, nil, errors.New("image format not recognized")
}

func parsePlatform(spec string) (*v1.Platform, error) {
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

func processRemoteImage(imageName string, username string, password string, platform string, onLayer LayerProcessor) (layerDigests map[int]string, layerIDs map[int]string, err error) {

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

	requestPlatform, err := parsePlatform(platform)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set platform: %w", err)
	}
	platformOpt := remote.WithPlatform(*requestPlatform)
	remoteOpts = append(remoteOpts, platformOpt)

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

func processImageLayers(ctx *cli.Context, onLayer LayerProcessor) (layerDigests map[int]string, layerIDs map[int]string, err error) {
	imageName := ctx.String(inputFlag)
	tarballPath := ctx.GlobalString(tarballFlag)
	useDocker := ctx.GlobalBool(dockerFlag)

	if useDocker && tarballPath != "" {
		return nil, nil, errors.New("cannot use both docker and tarball for image source")
	}

	processLocal := func(fetcher func(string) (io.ReadCloser, error), image string) (map[int]string, map[int]string, error) {
		imageReader, err := fetcher(image)
		if err != nil {
			return nil, nil, err
		}
		defer imageReader.Close()
		return processLocalImage(imageReader, onLayer)
	}

	if tarballPath != "" {
		return processLocal(fetchImageTarball, tarballPath)
	} else if useDocker {
		return processLocal(fetchImageDocker, imageName)
	} else {
		return processRemoteImage(
			imageName,
			ctx.String(usernameFlag),
			ctx.String(passwordFlag),
			ctx.String(platformFlag),
			onLayer,
		)
	}
}

func moveFile(src string, dst string) error {
	err := os.Rename(src, dst)

	// If a simple rename didn't work, for example moving to or from a mount,
	// then copy and delete the file
	if err != nil {
		sourceFile, err := os.Open(src)
		if err != nil {
			return err
		}
		defer sourceFile.Close()

		destFile, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer destFile.Close()

		if _, err = io.Copy(destFile, sourceFile); err != nil {
			return err
		}
		sourceFile.Close()

		if err = os.Remove(src); err != nil {
			return err
		}
	}

	return nil
}

func sanitiseVHDFilename(vhdFilename string) string {
	return strings.TrimSuffix(
		strings.ReplaceAll(vhdFilename, "/", "_"),
		".tar",
	)
}

func createVHD(layerID string, layerReader io.Reader, verityHashDev bool, outDir string) error {
	sanitisedFileName := sanitiseVHDFilename(layerID)

	// Create this file in a temp directory because at this point we don't have
	// the layer digest to properly name the file, it will be moved later
	vhdPath := filepath.Join(os.TempDir(), sanitisedFileName+".vhd")

	out, err := os.Create(vhdPath)
	if err != nil {
		return fmt.Errorf("failed to create layer vhd file %s: %w", vhdPath, err)
	}
	defer out.Close()

	opts := []tar2ext4.Option{
		tar2ext4.ConvertWhiteout,
		tar2ext4.MaximumDiskSize(maxVHDSize),
	}

	if !verityHashDev {
		opts = append(opts, tar2ext4.AppendDMVerity)
	}

	if err := tar2ext4.Convert(layerReader, out, opts...); err != nil {
		return fmt.Errorf("failed to convert tar to ext4: %w", err)
	}

	if verityHashDev {

		hashDevPath := filepath.Join(outDir, sanitisedFileName+".hash-dev.vhd")

		hashDev, err := os.Create(hashDevPath)
		if err != nil {
			return fmt.Errorf("failed to create hash device VHD file: %w", err)
		}
		defer hashDev.Close()

		if err := dmverity.ComputeAndWriteHashDevice(out, hashDev); err != nil {
			return err
		}

		if err := tar2ext4.ConvertToVhd(hashDev); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "hash device created at %s\n", hashDevPath)
	}
	if err := tar2ext4.ConvertToVhd(out); err != nil {
		return fmt.Errorf("failed to append VHD footer: %w", err)
	}
	return nil
}

var createVHDCommand = cli.Command{
	Name:  "create",
	Usage: "creates LCOW layer VHDs inside the output directory with dm-verity super block and merkle tree appended at the end",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     inputFlag + ",image,i",
			Usage:    "Required: container image reference or path directory tarfile to create a VHD from",
			Required: true,
		},
		cli.StringFlag{
			Name:     outputDirFlag + ",o",
			Usage:    "Required: output directory path",
			Required: true,
		},
		cli.StringFlag{
			Name:  usernameFlag + ",u",
			Usage: "Optional: custom registry username",
		},
		cli.StringFlag{
			Name:  passwordFlag + ",p",
			Usage: "Optional: custom registry password",
		},
		cli.BoolFlag{
			Name:  hashDeviceVhdFlag + ",hdv",
			Usage: "Optional: save hash-device as a VHD",
		},
		cli.BoolFlag{
			Name:  dataVhdFlag + ",dir",
			Usage: "Optional: save directory tarfile as a VHD",
		},
	},
	Action: func(ctx *cli.Context) error {
		verbose := ctx.GlobalBool(verboseFlag)
		if verbose {
			log.SetLevel(log.DebugLevel)
		}
		trace := ctx.GlobalBool(traceFlag)
		if trace {
			log.SetLevel(log.TraceLevel)
		}

		log.Trace("createVHDCommand called")

		verityHashDev := ctx.Bool(hashDeviceVhdFlag)
		verityData := ctx.Bool(dataVhdFlag)

		outDir := ctx.String(outputDirFlag)
		if _, err := os.Stat(outDir); os.IsNotExist(err) {
			log.Debugf("creating output directory %q", outDir)
			if err := os.MkdirAll(outDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory %s: %w", outDir, err)
			}
		}

		if verityData {
			dirName := ctx.String(inputFlag)
			log.Debugf("creating VHD from directory tarball at: %q", dirName)
			dirReader, err := fetchImageTarball(dirName)
			if err != nil {
				return fmt.Errorf("failed to get tar file reader from tarball %s: %w", dirName, err)
			}
			if err := createVHD(dirName, dirReader, verityHashDev, outDir); err != nil {
				return fmt.Errorf("failed to create VHD from directory %s: %w", dirName, err)
			}
			sanitisedDirName := sanitiseVHDFilename(dirName)
			src := filepath.Join(os.TempDir(), sanitisedDirName+".vhd")
			if _, err := os.Stat(src); os.IsNotExist(err) {
				return fmt.Errorf("directory VHD %s does not exist", src)
			}

			dst := filepath.Join(outDir, sanitisedDirName+".vhd")
			if err := moveFile(src, dst); err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "Directory VHD created at %s\n", dst)
			return nil
		}

		createVHDLayer := func(layerID string, layerReader io.Reader) error {
			return createVHD(layerID, layerReader, verityHashDev, outDir)
		}

		log.Debug("creating layer VHDs with dm-verity")
		layerDigests, layerIDs, err := processImageLayers(ctx, createVHDLayer)
		if err != nil {
			return err
		}

		// Move the VHDs to the output directory
		// They can't immediately be in the output directory because they have
		// temporary file names based on the layer id which isn't necessarily
		// the layer digest
		for layerNumber := 0; layerNumber < len(layerDigests); layerNumber++ {
			layerDigest := layerDigests[layerNumber]
			layerID := layerIDs[layerNumber]
			sanitisedFileName := sanitiseVHDFilename(layerID)

			suffixes := []string{".vhd"}

			for _, srcSuffix := range suffixes {
				src := filepath.Join(os.TempDir(), sanitisedFileName+srcSuffix)
				if _, err := os.Stat(src); os.IsNotExist(err) {
					return fmt.Errorf("layer VHD %s does not exist", src)
				}

				dst := filepath.Join(outDir, layerDigest+srcSuffix)
				if err := moveFile(src, dst); err != nil {
					return err
				}

				fmt.Fprintf(os.Stdout, "Layer VHD created at %s\n", dst)
			}

		}
		return nil
	},
}

var rootHashVHDCommand = cli.Command{
	Name:  "roothash",
	Usage: "compute root hashes for each LCOW layer VHD",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     inputFlag + ",image,i",
			Usage:    "Required: container image reference",
			Required: true,
		},
		cli.StringFlag{
			Name:  usernameFlag + ",u",
			Usage: "Optional: custom registry username",
		},
		cli.StringFlag{
			Name:  passwordFlag + ",p",
			Usage: "Optional: custom registry password",
		},
		cli.StringFlag{
			Name:  platformFlag,
			Usage: "Optional: the image platform",
		},
	},
	Action: func(ctx *cli.Context) error {
		verbose := ctx.GlobalBool(verboseFlag)
		if verbose {
			log.SetLevel(log.DebugLevel)
		}
		trace := ctx.GlobalBool(traceFlag)
		if trace {
			log.SetLevel(log.TraceLevel)
		}

		log.Trace("rootHashVHDCommand called")

		layerHashes := make(map[string]string)

		// Default platform to linux/amd64 if not specified
		if ctx.String(platformFlag) == "" {
			ctx.Set(platformFlag, "linux/amd64")
		}

		var getLayerHash LayerProcessor
		if strings.HasPrefix(ctx.String(platformFlag), "linux") {
			getLayerHash = func(layerDigest string, layerReader io.Reader) error {
				hash, err := tar2ext4.ConvertAndComputeRootDigest(layerReader)
				if err != nil {
					return err
				}
				layerHashes[layerDigest] = hash
				return nil
			}
		} else if strings.HasPrefix(ctx.String(platformFlag), "windows") {
			var cleanup func() error
			var err error
			getLayerHash, cleanup, err = windowsLayerHasher(layerHashes)
			if err != nil {
				return err
			}
			if cleanup != nil {
				defer cleanup()
			}
		} else {
			return fmt.Errorf("unsupported platform %q", ctx.String(platformFlag))
		}

		_, layerIDs, err := processImageLayers(ctx, getLayerHash)
		if err != nil {
			return err
		}
		log.Infof("Layer hashes: %+v", layerHashes)

		// Print the layer number to layer hash
		var missingLayers []int
		for layerNumber := 0; layerNumber < len(layerIDs); layerNumber++ {
			hash, ok := layerHashes[layerIDs[layerNumber]]
			if !ok {
				missingLayers = append(missingLayers, layerNumber)
				continue
			}
			fmt.Fprintf(os.Stdout, "Layer %d root hash: %s\n", layerNumber, hash)
		}
		if len(missingLayers) > 0 {
			return fmt.Errorf("missing root hashes for layers: %v", missingLayers)
		}

		return nil
	},
}
