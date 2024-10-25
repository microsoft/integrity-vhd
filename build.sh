#!/bin/sh
GOOS="windows" go build ./cmd/dmverity-vhd
GOOS="windows" go build ./cmd/tar2ext4
