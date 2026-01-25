package main

import (
	"io"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
)

func tarToExt4(tarReader io.Reader, out string, opts []tar2ext4.Option) (string, error) {
	return "", nil
}
