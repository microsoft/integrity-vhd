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
	log.Trace("sanitiseVHDFilename called")

	return strings.TrimSuffix(
		strings.ReplaceAll(vhdFilename, "/", "_"),
		".tar",
	)
}

func saveDirTarAsVhd(dirName string, verityHashDev bool, outDir string) (string, error) {
	log.Trace("saveDirTarAsVhd called")

	log.Debugf("creating VHD from directory tarball at: %q", dirName)
	dirReader, err := fetchImageTarball(dirName)
	if err != nil {
		return "", fmt.Errorf("failed to get tar file reader from tarball %s: %w", dirName, err)
	}
	defer dirReader.Close()
	rootHash, err := createVHDLayer(dirName, dirReader, verityHashDev, outDir)
	if err != nil {
		return "", fmt.Errorf("failed to create VHD from directory %s: %w", dirName, err)
	}
	sanitisedDirName := sanitiseVHDFilename(dirName)
	src := filepath.Join(os.TempDir(), sanitisedDirName+".vhd")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return "", fmt.Errorf("directory VHD %s does not exist", src)
	}

	dst := filepath.Join(outDir, sanitisedDirName+".vhd")
	if err := moveFile(src, dst); err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stdout, "Directory VHD created at %s\n", dst)
	return rootHash, nil
}

// createVHDLayer converts a single tar layer stream into an ext4 VHD (with an
// appended dm-verity Merkle tree + superblock, unless verityHashDev is set to
// instead write the hash device to a separate VHD). When the Merkle tree is
// appended to the data VHD, this also returns its root hash, read back from
// the just-written dm-verity superblock rather than recomputed via a second
// tar-to-ext4 pass.
func createVHDLayer(layerID string, layerReader io.Reader, verityHashDev bool, outDir string) (string, error) {
	log.Trace("createVHDLayer called")

	sanitisedFileName := sanitiseVHDFilename(layerID)

	// Create this file in a temp directory because at this point we don't have
	// the layer digest to properly name the file, it will be moved later
	vhdPath := filepath.Join(os.TempDir(), sanitisedFileName+".vhd")

	out, err := os.Create(vhdPath)
	if err != nil {
		return "", fmt.Errorf("failed to create layer vhd file %s: %w", vhdPath, err)
	}
	defer out.Close()

	opts := []tar2ext4.Option{
		tar2ext4.ConvertWhiteout,
		tar2ext4.MaximumDiskSize(maxVHDSize),
	}

	if err := tar2ext4.ConvertTarToExt4(layerReader, out, opts...); err != nil {
		return "", fmt.Errorf("failed to convert tar to ext4: %w", err)
	}

	// Record the offset where the ext4 data ends and (if requested) the
	// dm-verity Merkle tree/superblock begins, so the root hash can be read
	// back afterwards without a second tar-to-ext4 conversion pass.
	ext4DataSize, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", fmt.Errorf("failed to determine ext4 data size: %w", err)
	}

	var rootHash string
	if verityHashDev {
		hashDevPath := filepath.Join(outDir, sanitisedFileName+".hash-dev.vhd")

		hashDev, err := os.Create(hashDevPath)
		if err != nil {
			return "", fmt.Errorf("failed to create hash device VHD file: %w", err)
		}
		defer hashDev.Close()

		if err := dmverity.ComputeAndWriteHashDevice(out, hashDev); err != nil {
			return "", err
		}

		// Read the root hash back from the just-written hash device (starts
		// at offset 0) instead of a second tar-to-ext4 conversion pass.
		if _, err := hashDev.Seek(0, io.SeekStart); err != nil {
			return "", fmt.Errorf("failed to seek hash device: %w", err)
		}
		info, err := dmverity.ReadDMVerityInfoReader(hashDev)
		if err != nil {
			return "", fmt.Errorf("failed to read back dm-verity root hash: %w", err)
		}
		rootHash = info.RootDigest

		if err := tar2ext4.ConvertToVhd(hashDev); err != nil {
			return "", err
		}

		fmt.Fprintf(os.Stdout, "hash device created at %s\n", hashDevPath)
	} else {
		if err := dmverity.ComputeAndWriteHashDevice(out, out); err != nil {
			return "", err
		}

		info, err := dmverity.ReadDMVerityInfo(vhdPath, ext4DataSize)
		if err != nil {
			return "", fmt.Errorf("failed to read back dm-verity root hash: %w", err)
		}
		rootHash = info.RootDigest
	}

	if err := tar2ext4.ConvertToVhd(out); err != nil {
		return "", fmt.Errorf("failed to append VHD footer: %w", err)
	}
	return rootHash, nil
}

