package main

import (
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"


	"github.com/Microsoft/hcsshim/ext4/dmverity"
)

const (
	usernameFlag       = "username"
	passwordFlag       = "password"
	platformFlag       = "platform"
	inputFlag          = "input"
	outputFlag         = "output"
	typeFlag           = "type"
	verboseFlag        = "verbose"
	traceFlag          = "trace"
	profilerFlag       = "profiler" // enable profiling
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
		hashLayerCommand,
		tar2hashedCommand,
	}
	app.Usage = "dmverity-vhd is a command line tool for creating LCOW layer VHDs with dm-verity hashes and WCOW layer integrity checked CIMs."
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
		cli.StringFlag{
			Name:  profilerFlag,
			Usage: "Optional: profile and put the results in this file",
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
		setupProfiler(ctx)
		setLoggingLevel(ctx)
		log.Trace("createVHDCommand called")

		imageName, outDir, verityHashDev, verityData, imageFetcher, imageParser, manifestParser, err := parseCreateVhdArgs(ctx)
		if err != nil {
			return err
		}
		err = createVhd(imageFetcher, imageParser, manifestParser, imageName, outDir, verityHashDev, verityData)
		stopProfiler(ctx)
		return err
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
			Value: "linux/amd64",
		},
	},
	Action: func(ctx *cli.Context) error {
		setupProfiler(ctx)
		setLoggingLevel(ctx)
		log.Trace("rootHashVHDCommand called")

		imageFetcher, imageParser, manifestParser, layerParser, err := parseRoothashArgs(ctx)
		if err != nil {
			return err
		}
		err = roothash(imageFetcher, imageParser, manifestParser, layerParser)
		stopProfiler(ctx)
		return err
	},
}

var hashLayerCommand = cli.Command{
	Name:  "hashlayer",
	Usage: "compute root hashes for each LCOW layer VHD",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     inputFlag + ",t",
			Usage:    "Required: path to layer tar",
			Required: true,
		},
		cli.StringFlag{
			Name:  platformFlag,
			Usage: "Optional: the image platform",
			Value: "linux/amd64",
		},
	},
	Action: func(ctx *cli.Context) error {
		setupProfiler(ctx)
		setLoggingLevel(ctx)
		log.Trace("hashLayerCommand called")

		tarPath, platform, err := parseHashLayerArgs(ctx)
		if err != nil {
			return err
		}

		hash, err := hashLayer(tarPath, platform)
		fmt.Printf("%s\n", hash)
		log.Trace("hashLayer done")
		stopProfiler(ctx)
		return err
	},
}

var tar2hashedCommand = cli.Command{
	Name:  "tar2hashed",
	Usage: "convert from tar to integrity protected ext4fs or CIMfs",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     inputFlag + ",i",
			Usage:    "Required: path to layer tar",
			Required: true,
		},
		cli.StringFlag{
			Name:     outputFlag + ",o",
			Usage:    "Required: path to resulting file",
			Required: true,
		},
		cli.StringFlag{
			Name:     typeFlag + ",t",
			Usage:    "Required: output image type, cim or ext4",
			Required: true,
		},
	},
	Action: func(ctx *cli.Context) error {
		setupProfiler(ctx)
		setLoggingLevel(ctx)
		log.Trace("tar2hashedCommand called")

		srcTarPath := ctx.String(inputFlag)
		destPath := ctx.String(outputFlag)
		cimOrext4 := ctx.String(typeFlag)

		if cimOrext4 != "cim" && cimOrext4 != "ext4" {
			return errors.New("type must be either cim or ext4")
		}

		hash, err := tar2hashed(srcTarPath, destPath, cimOrext4)
		if err != nil {
			log.Infof("tar2hash failed: %s", err.Error())
		} else {
			log.Infof("%s", hash)
		}
		log.Trace("tar2hashedCommand done")
		stopProfiler(ctx)
		return nil
	},
}
