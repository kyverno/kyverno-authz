package utils

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"

	apixv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CrdExists(cfg *rest.Config, crdName string) (bool, error) {
	client, err := apixv1.NewForConfig(cfg)
	if err != nil {
		return false, err
	}

	_, err = client.ApiextensionsV1().
		CustomResourceDefinitions().
		Get(context.Background(), crdName, metav1.GetOptions{})

	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
