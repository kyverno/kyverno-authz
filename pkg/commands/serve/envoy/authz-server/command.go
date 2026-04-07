package authzserver

import (
	"context"
	"fmt"
	"os"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hairyhenderson/go-fsimpl"
	"github.com/hairyhenderson/go-fsimpl/filefs"
	"github.com/hairyhenderson/go-fsimpl/gitfs"
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/kyverno/kyverno-authz/apis"
	"github.com/kyverno/kyverno-authz/pkg/authz/envoy"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	vpolcompiler "github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	"github.com/kyverno/kyverno-authz/pkg/engine/sources"
	"github.com/kyverno/kyverno-authz/pkg/events"
	"github.com/kyverno/kyverno-authz/pkg/probes"
	"github.com/kyverno/kyverno-authz/pkg/signals"
	"github.com/kyverno/kyverno-authz/pkg/utils/ocifs"
	"github.com/kyverno/sdk/core"
	sdksources "github.com/kyverno/sdk/core/sources"
	openreportsclient "github.com/openreports/reports-api/pkg/client/clientset/versioned/typed/openreports.io/v1alpha1"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func Command() *cobra.Command {
	var (
		probesAddress         string
		metricsAddress        string
		grpcAddress           string
		grpcNetwork           string
		kubeConfigOverrides   clientcmd.ConfigOverrides
		externalPolicySources []string
		kubePolicySource      bool
		imagePullSecrets      []string
		allowInsecureRegistry bool
		msgFormat             string
		eventsEnabled         bool
		openreportsEnabled    bool
		reportFlushInterval   string
		resultBufSize         int
	)
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
					// load sources
					var source engine.EnvoySource
					var dyn dynamic.Interface

					// envoy type generics need to be pointers due to the fact that they are protos and contain mutexes
					envoyEventHandlers := []events.EventIface[*authv3.CheckRequest]{}
					envoyEventHandlers = append(envoyEventHandlers, events.NewWriterEventSubscriber[*authv3.CheckRequest](
						os.Stdout,
						logger,
						msgFormat,
					))

					if kubeOk {
						// Create kubernetes client
						kubeclient, err := kubernetes.NewForConfig(config)
						if err != nil {
							return err
						}
						// create dynamic client
						dynclient, err := dynamic.NewForConfig(config)
						if err != nil {
							return err
						}
						dyn = dynclient
						// initialize compiler
						compiler := vpolcompiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](dynclient)
						namespace, _, err := kubeConfig.Namespace()
						if err != nil {
							return fmt.Errorf("failed to get namespace from kubeconfig: %w", err)
						}
						if namespace == "" || namespace == "default" {
							logger.Info(fmt.Sprintf("Using namespace '%s' - consider setting explicit namespace", namespace))
						}

						// add the k8s events event handler
						if eventsEnabled {
							envoyEventHandlers = append(envoyEventHandlers,
								events.NewK8sEventSubscriber[*authv3.CheckRequest](
									kubeclient, namespace,
									logger, msgFormat))
						}

						// add the openreports event handler
						if openreportsEnabled {
							if exists, err := crdExists(config, "reports.openreports.io"); err == nil && exists {
								orClient, err := openreportsclient.NewForConfig(config)
								if err != nil {
									logger.Error(err, "failed to instantiate openreports client")
								} else {
									// the parse duration function returns a zero duration on error
									// hence why we need to create a pointer variable to easily differentiate the absence of this value
									var intervalPtr *time.Duration
									flushInterval, err := time.ParseDuration(reportFlushInterval)
									if err == nil {
										intervalPtr = &flushInterval
									} else {
										logger.Info("error parsing the reports flush interval, will push results to the report immediately")
									}
									// todo: customize the report name based on pod name
									envoyEventHandlers = append(envoyEventHandlers, events.NewOpenreportsSubscriber[*authv3.CheckRequest](
										resultBufSize,
										orClient, intervalPtr, logger,
										"envoy-authz-report", namespace, msgFormat))
								}
							}
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
											Field: fields.OneTermEqualSelector("spec.evaluation.mode", string(apis.EvaluationModeEnvoy)),
										},
									},
								},
							})
							if err != nil {
								return fmt.Errorf("failed to construct manager: %w", err)
							}
							kubeSource, err := sources.NewKube("envoy", mgr, compiler)
							if err != nil {
								return fmt.Errorf("failed to create envoy source: %w", err)
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
								return fmt.Errorf("failed to wait for envoy cache sync")
							}
						}
					} else {
						rOpts, nOpts, err := ocifs.RegistryOpts(nil, allowInsecureRegistry)
						if err != nil {
							return fmt.Errorf("failed to initialize registry opts: %w", err)
						}
						// initialize compiler
						compiler := vpolcompiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil)
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

					ev := events.NewComposite(envoyEventHandlers...)
					// auth server
					authServer := envoy.NewServer(grpcNetwork, grpcAddress, source, dyn, ev)
					group.StartWithContext(ctx, func(ctx context.Context) {
						// grpc auth server
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
	command.Flags().StringVar(&grpcAddress, "grpc-address", ":9081", "Address to listen on")
	command.Flags().StringVar(&grpcNetwork, "grpc-network", "tcp", "Network to listen on")
	command.Flags().StringVar(&metricsAddress, "metrics-address", ":9082", "Address to listen on for metrics")
	command.Flags().StringArrayVar(&externalPolicySources, "external-policy-source", nil, "External policy sources")
	command.Flags().StringArrayVar(&imagePullSecrets, "image-pull-secret", nil, "Image pull secrets")
	command.Flags().BoolVar(&allowInsecureRegistry, "allow-insecure-registry", false, "Allow insecure registry")
	command.Flags().BoolVar(&kubePolicySource, "kube-policy-source", true, "Enable in-cluster kubernetes policy source")
	command.Flags().BoolVar(&eventsEnabled, "events-enabled", false, "Enable k8s events on authz, if not running in k8s this flag wont take effect")
	command.Flags().BoolVar(&openreportsEnabled, "openreports-enabled", false, "Enable reporting in the openreports format, if not running in k8s or the openreports CRD is not installed this flag wont take effect")
	command.Flags().StringVar(&reportFlushInterval, "report-flush-interval", "", "how often do results get flushed into the openreports report (if active)")
	command.Flags().StringVar(&msgFormat, "log-msg-format", "[%s] http: request %s, response: %s\n", "The format in which request logs would be shown in stdout")
	command.Flags().IntVar(&resultBufSize, "result-buffer-size", 500, "Event buffer size for openreports, note that if the total exceeded the 1MB etcd limit, report flushing will error")
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

// ammar: move this to a generic utils file
func crdExists(cfg *rest.Config, crdName string) (bool, error) {
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
