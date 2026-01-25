package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/ext4/dmverity"
	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	log "github.com/sirupsen/logrus"
)

func sanitiseVHDFilename(vhdFilename string) string {
	return strings.TrimSuffix(
		strings.ReplaceAll(vhdFilename, "/", "_"),
		".tar",
	)
}

func saveDirTarAsVhd(dirName string, verityHashDev bool, outDir string) error {
	log.Debugf("creating VHD from directory tarball at: %q", dirName)
	dirReader, err := fetchImageTarball(dirName)
	if err != nil {
		return fmt.Errorf("failed to get tar file reader from tarball %s: %w", dirName, err)
	}
	if err := createVHDLayer(dirName, dirReader, verityHashDev, outDir); err != nil {
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

func createVHDLayer(layerID string, layerReader io.Reader, verityHashDev bool, outDir string) error {
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
