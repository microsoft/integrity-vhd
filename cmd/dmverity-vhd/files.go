package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
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

func fetchImageTarball(tarballPath string) (imageReader io.ReadCloser, err error) {
	log.Tracef("fetchImageTarball called for tarball: %s", tarballPath)
	TraceMemUsage()

	if imageReader, err = os.Open(tarballPath); err != nil {
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

	if err == nil {
		return io.MultiReader(&header, reader), true
	}

	if err == io.EOF {
		buf := header.Bytes()
		if len(buf) >= 512 {
			emptyHeader := true
			for _, b := range buf[:512] {
				if b != 0 {
					emptyHeader = false
					break
				}
			}
			if emptyHeader {
				return io.MultiReader(&header, reader), true
			}
		}
	}

	return io.MultiReader(&header, reader), false
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
