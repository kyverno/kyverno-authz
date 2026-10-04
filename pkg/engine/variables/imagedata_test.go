package variables

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

func TestImageData(t *testing.T) {
	server := httptest.NewServer(registry.New())
	defer server.Close()

	ref, err := name.NewTag(strings.TrimPrefix(server.URL, "http://") + "/test/image:latest")
	require.NoError(t, err)
	image, err := random.Image(1024, 1)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, image))
	digest, err := image.Digest()
	require.NoError(t, err)

	loader, err := ImageData(nil)
	require.NoError(t, err)
	data, err := loader.GetImageData(ref.Name(), nil)
	require.NoError(t, err)
	require.Equal(t, digest.String(), data["digest"])
	require.Equal(t, "latest", data["tag"])
	require.NotNil(t, data["manifest"])
	require.NotNil(t, data["config"])
}

func TestImageDataInvalidReference(t *testing.T) {
	loader, err := ImageData(nil)
	require.NoError(t, err)
	_, err = loader.GetImageData("not a valid image reference", nil)
	require.Error(t, err)
}
