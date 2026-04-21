package sources

import (
	"context"
	"fmt"
	"io/fs"
	"sync"

	"k8s.io/klog/v2"

	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	vpolv1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	vpolv1alpha1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	vpolv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/kyverno/kyverno-authz/pkg/data"
	"github.com/kyverno/pkg/ext/file"
	"github.com/kyverno/pkg/ext/resource/convert"
	"github.com/kyverno/pkg/ext/resource/loader"
	"github.com/kyverno/pkg/ext/yaml"
	"sigs.k8s.io/kubectl-validate/pkg/openapiclient"
)

var (
	vpolGVKv1alpha1  = vpolv1alpha1.SchemeGroupVersion.WithKind("ValidatingPolicy")
	vpolGVKv1beta1   = vpolv1beta1.SchemeGroupVersion.WithKind("ValidatingPolicy")
	vpolGVKv1        = vpolv1.SchemeGroupVersion.WithKind("ValidatingPolicy")
	polexGVKv1alpha1 = vpolv1alpha1.SchemeGroupVersion.WithKind("PolicyException")
	polexGVKv1beta1  = vpolv1beta1.SchemeGroupVersion.WithKind("PolicyException")
	polexGVKv1       = vpolv1.SchemeGroupVersion.WithKind("PolicyException")
)

type document = []byte

func defaultLoader(_fs func() (fs.FS, error)) (loader.Loader, error) {
	if _fs == nil {
		_fs = data.Crds
	}
	crdsFs, err := _fs()
	if err != nil {
		return nil, err
	}
	return loader.New(openapiclient.NewLocalCRDFiles(crdsFs))
}

var DefaultLoader = sync.OnceValues(func() (loader.Loader, error) { return defaultLoader(nil) })

func LoadPolicies(f fs.FS) ([]*vpolv1.ValidatingPolicy, []*vpolv1.PolicyException, error) {
	policies := []*vpolv1.ValidatingPolicy{}
	policyExceptions := []*vpolv1.PolicyException{}

	err := fs.WalkDir(f, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry == nil {
			klog.Errorf("skipping entry %s: walk error: %v", path, walkErr)
			return nil
		}
		// process only files
		if entry.IsDir() {
			return nil
		}
		if !file.IsYaml(entry.Name()) && !file.IsJson(entry.Name()) {
			return nil
		}
		docs, err := getDocuments(context.Background(), f, entry)
		if err != nil {
			klog.Errorf("skipping entry %s: failed to read documents: %v", entry.Name(), err)
			return nil
		}
		for _, doc := range docs {
			ldr, err := DefaultLoader()
			if err != nil {
				klog.Errorf("skipping entry %s: failed to create loader: %v", entry.Name(), err)
				return nil
			}
			gvk, untyped, err := ldr.Load(doc)
			if err != nil {
				klog.Errorf("skipping document in %s: failed to load: %v", entry.Name(), err)
				continue
			}
			switch gvk {
			case vpolGVKv1alpha1, vpolGVKv1beta1, vpolGVKv1:
				typed, err := convert.To[vpolv1.ValidatingPolicy](untyped)
				if err != nil {
					klog.Errorf("skipping document in %s: failed to convert to ValidatingPolicy: %v", entry.Name(), err)
					continue
				}
				policies = append(policies, typed)
			case polexGVKv1, polexGVKv1alpha1, polexGVKv1beta1:
				typed, err := convert.To[v1.PolicyException](untyped)
				if err != nil {
					klog.Errorf("skipping document in %s: failed to convert to PolicyException: %v", entry.Name(), err)
					continue
				}
				policyExceptions = append(policyExceptions, typed)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return policies, policyExceptions, nil
}

func getDocuments(_ context.Context, f fs.FS, entry fs.DirEntry) ([]document, error) {
	if entry == nil {
		return nil, nil
	}
	// if it's a yaml file, it can contain multiple documents
	if file.IsYaml(entry.Name()) {
		bytes, err := fs.ReadFile(f, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", entry.Name(), err)
		}
		documents, err := yaml.SplitDocuments(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to split documents: %w", err)
		}
		return documents, nil
	}
	// if it's a json file, it contains a single document
	if file.IsJson(entry.Name()) {
		doc, err := fs.ReadFile(f, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", entry.Name(), err)
		}
		return []document{doc}, nil
	}
	return nil, nil
}
