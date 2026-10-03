package variables

import (
	"context"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/sdk/extensions/cel/utils"
	"github.com/kyverno/sdk/extensions/imagedataloader"
	v1 "k8s.io/client-go/listers/core/v1"
)

func ImageData(lister v1.SecretLister, imageOpts ...remote.Option) (*imageData, error) {
	// TODO: secrets interface
	idl, err := imagedataloader.New(lister, imageOpts, nil)
	if err != nil {
		return nil, err
	}
	return &imageData{
		imagedata: idl,
	}, nil
}

type imageData struct {
	imagedata imagedataloader.Fetcher
}

func (cp *imageData) GetImageData(image string, imageOpts []remote.Option) (map[string]any, error) {
	// TODO: get image credentials from image verification policies?
	data, err := cp.imagedata.FetchImageData(context.TODO(), image, imageOpts, nil)
	if err != nil {
		return nil, err
	}
	return utils.GetValue(data.Data())
}
