package validationwebhook

import (
	"context"
	"fmt"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	vpolv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/kyverno/kyverno-authz/apis/v1alpha1"
	vpolcompiler "github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	"github.com/kyverno/kyverno-authz/pkg/probes"
	"github.com/kyverno/kyverno-authz/pkg/signals"
	"github.com/kyverno/kyverno-authz/pkg/webhook/validation"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func Command() *cobra.Command {
	var probesAddress string
	var metricsAddress string
	var kubeConfigOverrides clientcmd.ConfigOverrides
	command := &cobra.Command{
		Use:   "validation-webhook",
		Short: "Start the validation webhook",
		RunE: func(cmd *cobra.Command, args []string) error {
			// setup signals aware context
			return signals.Do(context.Background(), func(ctx context.Context) error {
				// track errors
				var httpErr, grpcErr, mgrErr error
				err := func(ctx context.Context) error {
					// create a rest config
					kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
						clientcmd.NewDefaultClientConfigLoadingRules(),
						&kubeConfigOverrides,
					)
					config, err := kubeConfig.ClientConfig()
					if err != nil {
						return err
					}
					// create a wait group
					var group wait.Group
					// wait all tasks in the group are over
					defer group.Wait()
					// create a controller manager
					scheme := runtime.NewScheme()
					if err := vpolv1beta1.Install(scheme); err != nil {
						return err
					}
					mgr, err := ctrl.NewManager(config, ctrl.Options{
						Scheme: scheme,
						Metrics: metricsserver.Options{
							BindAddress: metricsAddress,
						},
						LeaderElection: false,
					})
					if err != nil {
						return fmt.Errorf("failed to construct manager: %w", err)
					}
					envoyCompiler := vpolcompiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse]()
					vpolCompileFunc := func(policy *vpolv1beta1.ValidatingPolicy) field.ErrorList {
						if policy.Spec.EvaluationMode() == v1alpha1.EvaluationModeEnvoy {
							_, err := envoyCompiler.Compile(policy)
							ctrl.LoggerFrom(ctx).Error(err.ToAggregate(), "Validating policy compilation error")
							return err
						}
						return nil
					}
					v := validation.NewValidator(vpolCompileFunc)
					if err := ctrl.NewWebhookManagedBy(mgr).For(&vpolv1beta1.ValidatingPolicy{}).WithValidator(v).Complete(); err != nil {
						return fmt.Errorf("failed to create webhook: %w", err)
					}
					// create a cancellable context
					ctx, cancel := context.WithCancel(ctx)
					// start manager
					group.StartWithContext(ctx, func(ctx context.Context) {
						// cancel context at the end
						defer cancel()
						mgrErr = mgr.Start(ctx)
					})
					// create http and grpc servers
					http := probes.NewServer(probesAddress)
					// run servers
					group.StartWithContext(ctx, func(ctx context.Context) {
						// cancel context at the end
						defer cancel()
						httpErr = http.Run(ctx)
					})
					return nil
				}(ctx)
				return multierr.Combine(err, httpErr, grpcErr, mgrErr)
			})
		},
	}
	command.Flags().StringVar(&probesAddress, "probes-address", ":9080", "Address to listen on for health checks")
	command.Flags().StringVar(&metricsAddress, "metrics-address", ":9082", "Address to listen on for metrics")
	clientcmd.BindOverrideFlags(&kubeConfigOverrides, command.Flags(), clientcmd.RecommendedConfigOverrideFlags("kube-"))
	return command
}
