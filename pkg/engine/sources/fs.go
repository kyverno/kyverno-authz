package sources

import (
	"context"
	"fmt"
	"io/fs"
	"sync"

	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	vpolv1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	vpolv1alpha1 "github.com/kyverno/api/api/policies.kyverno.io/v1alpha1"
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

	// we pass the error here because it comes from before calling the predicate ?
	err := fs.WalkDir(f, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if entry == nil {
			return nil
		}
		// process only files
		if entry.IsDir() {
			return nil
		}
		if !file.IsYaml(entry.Name()) || !file.IsJson(entry.Name()) {
			return nil
		}
		docs, err := getDocuments(context.Background(), f, entry)
		if err != nil {
			return err
		}
		for _, doc := range docs {
			ldr, err := DefaultLoader()
			if err != nil {
				return fmt.Errorf("failed to load CRDs: %w", err)
			}
			gvk, untyped, err := ldr.Load(doc)
			if err != nil {
				return err
			}

			switch gvk {
			case vpolGVKv1alpha1, vpolGVKv1beta1, vpolGVKv1:
				typed, err := convert.To[vpolv1.ValidatingPolicy](untyped)
				if err != nil {
					return fmt.Errorf("failed to convert to ValidatingPolicy: %w", err)
				}
				policies = append(policies, typed)
			case polexGVKv1, polexGVKv1alpha1, polexGVKv1beta1:
				typed, err := convert.To[v1.PolicyException](untyped)
				if err != nil {
					return fmt.Errorf("failed to convert to ValidatingPolicy: %w", err)
				}
				policyExceptions = append(policyExceptions, typed)
			}
		}
		// Propagate traversal errors (e.g., permission denied, fs.SkipDir).
		return walkErr
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
	// process only files
	if entry.IsDir() {
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
