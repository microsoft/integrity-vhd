package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/ext4/dmverity"
	"github.com/Microsoft/hcsshim/ext4/tar2ext4"

	"compress/gzip"
)

// decompressIfNeeded checks if the data is gzip-compressed and returns a reader
func decompressIfNeeded(data []byte) (io.Reader, error) {
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		return gzip.NewReader(bytes.NewReader(data))
	}
	return bytes.NewReader(data), nil
}

const usage = `dmverity-vhd is a command line tool for creating LCOW layer VHDs with dm-verity hashes.`

const (
	usernameFlag       = "username"
	passwordFlag       = "password"
	inputFlag          = "input"
	verboseFlag        = "verbose"
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
		DisableTimestamp: true,
	})

	log.SetOutput(os.Stdout)

	log.SetLevel(log.WarnLevel)
}

func main() {
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
	if imageReader, err = os.Open(tarballPath); err != nil {
		return nil, err
	}

	return imageReader, err
}

func fetchImageDocker(imageName string) (imageReader io.ReadCloser, err error) {

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

func getLayerDigestsV24(configData []byte) (map[int]string, error) {
	type RootFs struct {
		DiffIDs []string `json:"diff_ids"`
	}
	type configLayerV24 struct {
		RootFS RootFs `json:"rootfs"`
	}

	var config configLayerV24
	if err := json.Unmarshal(configData, &config); err != nil || len(config.RootFS.DiffIDs) == 0 {
		return nil, errors.New("could not unmarshall json file for v24 config format")
	}

	layerDigests := make(map[int]string)
	for layerNumber, layerID := range config.RootFS.DiffIDs {
		layerIDSplit := strings.Split(layerID, ":")
		layerDigests[layerNumber] = layerIDSplit[len(layerIDSplit)-1]
	}
	return layerDigests, nil
}

func getLayerDigestsV25(configData []byte) (map[int]string, error) {
	type configLayerV25 []struct {
		Layers []string `json:"Layers"`
	}

	var config configLayerV25
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, err
	}

	layerDigests := make(map[int]string)
	for layerNumber, layerID := range config[0].Layers {

		if !strings.HasPrefix(layerID, "blobs") {
			return nil, errors.New("layer path isn't v25")
		}

		layerIDSplit := strings.Split(layerID, "/")
		layerDigests[layerNumber] = layerIDSplit[len(layerIDSplit)-1]
	}
	return layerDigests, nil
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

func processLocalImage(imageReader io.Reader, onLayer LayerProcessor) (map[int]string, map[int]string, error) {
	imageFileReader := tar.NewReader(imageReader)
	files := make(map[string][]byte)

	layerIDs := make(map[int]string)
	layerDigestCandidates := make(map[string]map[int]string)
	var configPath string

	for {
		hdr, err := imageFileReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		if hdr.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(imageFileReader)
			if err != nil {
				return nil, nil, err
			}
			files[hdr.Name] = data
		}
	}

	// OCI parsing first
	if indexData, ok := files["index.json"]; ok {
		log.Info("OCI image format detected (index.json found).")
		var index struct {
			Manifests []struct {
				Digest string `json:"digest"`
			} `json:"manifests"`
		}
		if err := json.Unmarshal(indexData, &index); err != nil {
			return nil, nil, fmt.Errorf("failed parsing OCI index.json: %w", err)
		}

		if len(index.Manifests) == 0 {
			return nil, nil, errors.New("no manifests found in OCI index.json")
		}

		manifestDigest := index.Manifests[0].Digest
		log.Infof("Using OCI manifest digest: %s", manifestDigest)

		manifestBlobPath := filepath.Join("blobs", strings.Replace(manifestDigest, ":", "/", 1))
		manifestData, ok := files[manifestBlobPath]
		if !ok {
			return nil, nil, fmt.Errorf("OCI manifest blob %s missing", manifestBlobPath)
		}

		var manifest struct {
			Config struct {
				Digest string `json:"digest"`
			} `json:"config"`
			Layers []struct {
				Digest string `json:"digest"`
			} `json:"layers"`
		}
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return nil, nil, fmt.Errorf("failed parsing OCI manifest: %w", err)
		}

		layerDigests := make(map[int]string)
		for i, layer := range manifest.Layers {
			layerBlobPath := filepath.Join("blobs", strings.Replace(layer.Digest, ":", "/", 1))
			layerBlob, ok := files[layerBlobPath]
			if !ok {
				return nil, nil, fmt.Errorf("OCI layer blob %s missing", layerBlobPath)
			}

			log.Infof("Processing OCI layer %d with digest: %s", i, layer.Digest)

			layerReader, err := decompressIfNeeded(layerBlob)
			if err != nil {
				return nil, nil, err
			}

			layerID := strings.SplitN(layer.Digest, ":", 2)[1]
			layerDigests[i] = layerID
			layerIDs[i] = layerID

			if err := onLayer(layerID, layerReader); err != nil {
				return nil, nil, err
			}
		}
		return layerDigests, layerIDs, nil
	}

	// Docker legacy fallback
	if manifestData, ok := files["manifest.json"]; ok {
		log.Info("Docker legacy image format detected (manifest.json found).")
		type Manifest []struct {
			Config string   `json:"Config"`
			Layers []string `json:"Layers"`
		}
		var manifest Manifest
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return nil, nil, err
		}

		configPath = manifest[0].Config
		log.Infof("Using Docker config file: %s", configPath)

		for layerNumber, layerID := range manifest[0].Layers {
			layerIDs[layerNumber] = layerID
			log.Infof("Found Docker layer %d: %s", layerNumber, layerID)
		}

		for fileName, configData := range files {
			parsingFuncs := []func([]byte) (map[int]string, error){
				getLayerDigestsV25,
				getLayerDigestsV24,
			}

			for _, parseFunc := range parsingFuncs {
				layerDigestCandidate, err := parseFunc(configData)
				if err == nil {
					layerDigestCandidates[fileName] = layerDigestCandidate
					log.Infof("Successfully parsed Docker config file: %s", fileName)
					break
				}
			}
		}

		layerDigests, ok := layerDigestCandidates[configPath]
		if !ok {
			return nil, nil, errors.New("Docker config file either not found or failed to parse")
		}

		// Call onLayer for Docker layers
		for i, layerFile := range manifest[0].Layers {
			layerBlob, ok := files[layerFile]
			if !ok {
				return nil, nil, fmt.Errorf("Docker layer file %s missing", layerFile)
			}

			log.Infof("Processing Docker layer %d: %s", i, layerFile)

			layerReader, err := decompressIfNeeded(layerBlob)
			if err != nil {
				return nil, nil, err
			}

			layerID := strings.Split(layerDigests[i], ":")[0]
			layerIDs[i] = layerID

			if err := onLayer(layerID, layerReader); err != nil {
				return nil, nil, err
			}
		}

		return layerDigests, layerIDs, nil
	}

	log.Warn("No recognizable OCI or Docker manifest found in provided tarball.")
	return nil, nil, errors.New("no recognizable image format found")
}

func processRemoteImage(imageName string, username string, password string, onLayer LayerProcessor) (layerDigests map[int]string, layerIDs map[int]string, err error) {

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
	},
	Action: func(ctx *cli.Context) error {
		verbose := ctx.GlobalBool(verboseFlag)
		if verbose {
			log.SetLevel(log.DebugLevel)
		}

		layerHashes := make(map[string]string)
		getLayerHash := func(layerDigest string, layerReader io.Reader) error {
			hash, err := tar2ext4.ConvertAndComputeRootDigest(layerReader)
			if err != nil {
				return err
			}
			layerHashes[layerDigest] = hash
			return nil
		}

		_, layerIDs, err := processImageLayers(ctx, getLayerHash)
		if err != nil {
			return err
		}

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
