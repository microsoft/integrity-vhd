package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/ext4/dmverity"
)

const (
	usernameFlag       = "username"
	passwordFlag       = "password"
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
	app.Usage = "dmverity-vhd is a command line tool for creating LCOW layer VHDs with dm-verity hashes."
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
		setLoggingLevel(ctx)

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
		layerDigests, layerIDs, err := parseImage(ctx, createVHDLayer)
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
		setLoggingLevel(ctx)
		log.Trace("rootHashVHDCommand called")

		imageFetcher, imageParser, manifestParser, layerParser, err := parseRoothashArgs(ctx)
		if err != nil {
			return err
		}
		return roothash(imageFetcher, imageParser, manifestParser, layerParser)
	},
}
