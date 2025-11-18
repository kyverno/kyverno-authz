package authzserver

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hairyhenderson/go-fsimpl"
	"github.com/hairyhenderson/go-fsimpl/filefs"
	"github.com/hairyhenderson/go-fsimpl/gitfs"
	"github.com/kyverno/kyverno-authz/apis/v1alpha1"
	"github.com/kyverno/kyverno-authz/pkg/authz/http"
	httplib "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	vpolcompiler "github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	"github.com/kyverno/kyverno-authz/pkg/engine/sources"
	"github.com/kyverno/kyverno-authz/pkg/probes"
	"github.com/kyverno/kyverno-authz/pkg/signals"
	"github.com/kyverno/kyverno-authz/pkg/utils/ocifs"
	"github.com/kyverno/kyverno-authz/sdk/core"
	sdksources "github.com/kyverno/kyverno-authz/sdk/core/sources"
	vpol "github.com/kyverno/kyverno/api/policies.kyverno.io/v1alpha1"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func Command() *cobra.Command {
	var probesAddress string
	var metricsAddress string
	var serverAddress string
	var kubeConfigOverrides clientcmd.ConfigOverrides
	var externalPolicySources []string
	var kubePolicySource bool
	var imagePullSecrets []string
	var allowInsecureRegistry bool
	var nestedRequest bool
	var certFile string
	var keyFile string
	var inputExpression string
	var outputExpression string
	command := &cobra.Command{
		Use:   "authz-server",
		Short: "Start the Kyverno Authz Server",
		RunE: func(cmd *cobra.Command, args []string) error {
			// setup signals aware context
			return signals.Do(context.Background(), func(ctx context.Context) error {
				// track errors
				var probesErr, serverErr, mgrErr error
				err := func(ctx context.Context) error {
					logger := ctrl.LoggerFrom(ctx)
					kubeOk := true
					// create a rest config
					kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
						clientcmd.NewDefaultClientConfigLoadingRules(),
						&kubeConfigOverrides,
					)
					config, err := kubeConfig.ClientConfig()
					if err != nil {
						logger.Info("Warning, no kubernetes cluster configuration found, some features will be disabled")
						kubeOk = false
					}
					// create a cancellable context
					ctx, cancel := context.WithCancel(ctx)
					// cancel context at the end
					defer cancel()
					// create a wait group
					var group wait.Group
					// wait all tasks in the group are over
					defer group.Wait()
					// initialize compiler
					compiler := vpolcompiler.NewCompiler[dynamic.Interface, *httplib.CheckRequest, *httplib.CheckResponse]()
					// load sources
					var source engine.HTTPSource
					var dyn dynamic.Interface
					if kubeOk {
						// Create kubernetes client
						kubeclient, err := kubernetes.NewForConfig(config)
						if err != nil {
							return err
						}
						namespace, _, err := kubeConfig.Namespace()
						if err != nil {
							return fmt.Errorf("failed to get namespace from kubeconfig: %w", err)
						}
						if namespace == "" || namespace == "default" {
							logger.Info(fmt.Sprintf("Using namespace '%s' - consider setting explicit namespace", namespace))
						}
						rOpts, nOpts, err := ocifs.RegistryOpts(kubeclient.CoreV1().Secrets(namespace), allowInsecureRegistry, imagePullSecrets...)
						if err != nil {
							return fmt.Errorf("failed to initialize registry opts: %w", err)
						}
						extSources, err := getExternalSources(compiler, nOpts, rOpts, externalPolicySources...)
						if err != nil {
							return err
						}
						source = sdksources.NewComposite(extSources...)
						// if kube policy source is enabled
						if kubePolicySource {
							// create a controller manager
							scheme := runtime.NewScheme()
							if err := vpol.Install(scheme); err != nil {
								return err
							}
							mgr, err := ctrl.NewManager(config, ctrl.Options{
								Scheme: scheme,
								Metrics: metricsserver.Options{
									BindAddress: metricsAddress,
								},
								Cache: cache.Options{
									ByObject: map[client.Object]cache.ByObject{
										&vpol.ValidatingPolicy{}: {
											Field: fields.OneTermEqualSelector("spec.evaluation.mode", string(v1alpha1.EvaluationModeHTTP)),
										},
									},
								},
							})
							if err != nil {
								return fmt.Errorf("failed to construct manager: %w", err)
							}
							kubeSource, err := sources.NewKube("http", mgr, compiler)
							if err != nil {
								return fmt.Errorf("failed to create http source: %w", err)
							}
							source = sdksources.NewComposite(kubeSource, source)
							// start manager
							group.StartWithContext(ctx, func(ctx context.Context) {
								// cancel context at the end
								defer cancel()
								mgrErr = mgr.Start(ctx)
							})
							if !mgr.GetCache().WaitForCacheSync(ctx) {
								defer cancel()
								return fmt.Errorf("failed to wait for http cache sync")
							}
						}
						dynclient, err := dynamic.NewForConfig(config)
						if err != nil {
							return err
						}
						dyn = dynclient
					} else {
						rOpts, nOpts, err := ocifs.RegistryOpts(nil, allowInsecureRegistry)
						if err != nil {
							return fmt.Errorf("failed to initialize registry opts: %w", err)
						}
						extSources, err := getExternalSources(compiler, nOpts, rOpts, externalPolicySources...)
						if err != nil {
							return err
						}
						source = sdksources.NewComposite(extSources...)
					}
					// probes server
					if probesAddress != "" {
						probesServer := probes.NewServer(probesAddress)
						group.StartWithContext(ctx, func(ctx context.Context) {
							defer cancel()
							probesErr = probesServer.Run(ctx)
						})
					}
					// auth server
					httpConfig := http.Config{
						Address:          serverAddress,
						NestedRequest:    nestedRequest,
						CertFile:         certFile,
						KeyFile:          keyFile,
						InputExpression:  inputExpression,
						OutputExpression: outputExpression,
					}
					authServer := http.NewServer(httpConfig, source, dyn)
					group.StartWithContext(ctx, func(ctx context.Context) {
						defer cancel()
						serverErr = authServer.Run(ctx)
					})
					return nil
				}(ctx)
				return multierr.Combine(err, probesErr, serverErr, mgrErr)
			})
		},
	}
	command.Flags().StringVar(&probesAddress, "probes-address", "", "Address to listen on for health checks")
	command.Flags().StringVar(&metricsAddress, "metrics-address", ":9082", "Address to listen on for metrics")
	command.Flags().StringArrayVar(&externalPolicySources, "external-policy-source", nil, "External policy sources")
	command.Flags().StringArrayVar(&imagePullSecrets, "image-pull-secret", nil, "Image pull secrets")
	command.Flags().BoolVar(&allowInsecureRegistry, "allow-insecure-registry", false, "Allow insecure registry")
	command.Flags().BoolVar(&kubePolicySource, "kube-policy-source", true, "Enable in-cluster kubernetes policy source")
	command.Flags().StringVar(&serverAddress, "server-address", ":9081", "Address to serve the http authorization server on")
	command.Flags().BoolVar(&nestedRequest, "nested-request", false, "Expect the requests to validate to be in the body of the original request")
	command.Flags().StringVar(&inputExpression, "input-expression", "", "CEL expression for transforming the incoming request")
	command.Flags().StringVar(&outputExpression, "output-expression", "", "CEL expression for transforming responses before being sent to clients")
	command.Flags().StringVar(&certFile, "cert-file", "", "File containing tls certificate")
	command.Flags().StringVar(&keyFile, "key-file", "", "File containing tls private key")
	clientcmd.BindOverrideFlags(&kubeConfigOverrides, command.Flags(), clientcmd.RecommendedConfigOverrideFlags("kube-"))
	return command
}

func getExternalSources[POLICY any](vpolCompiler engine.Compiler[POLICY], nOpts []name.Option, rOpts []remote.Option, urls ...string) ([]core.Source[POLICY], error) {
	mux := fsimpl.NewMux()
	mux.Add(filefs.FS)
	// mux.Add(httpfs.FS)
	// mux.Add(blobfs.FS)
	mux.Add(gitfs.FS)

	// Create a configured ocifs.FS with registry options
	configuredOCIFS := ocifs.ConfigureOCIFS(nOpts, rOpts)
	mux.Add(configuredOCIFS)

	var providers []core.Source[POLICY]
	for _, url := range urls {
		fsys, err := mux.Lookup(url)
		if err != nil {
			return nil, err
		}
		providers = append(
			providers,
			sdksources.NewOnce(sources.NewFs(fsys, vpolCompiler)),
		)
	}
	return providers, nil
}
