package client // import "github.com/docker/docker/client"

import (
	"context"
	"io"
	"net/url"
	"fmt"
)

// ImageSave retrieves one or more images from the docker host as an io.ReadCloser.
// It's up to the caller to store the images and close the stream.
func (cli *Client) ImageSave(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
	fmt.Printf("ImageSave %v", imageIDs)
	query := url.Values{
		"names": imageIDs,
	}

	resp, err := cli.get(ctx, "/images/get", query, nil)
	if err != nil {
		println("ImageSave err %v", err)
		return nil, err
	}
	return resp.body, nil
}
