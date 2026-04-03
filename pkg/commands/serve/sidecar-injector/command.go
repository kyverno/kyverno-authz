package sidecarinjector

import (
	"context"
	"path/filepath"

	"github.com/kyverno/kyverno-authz/pkg/certmanager"
	"github.com/kyverno/kyverno-authz/pkg/sidecar"
	"github.com/kyverno/kyverno-authz/pkg/signals"
	"github.com/kyverno/kyverno-authz/pkg/webhook/mutation"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
)

func Command() *cobra.Command {
	var address string
	var certFile string
	var keyFile string
	var configFile string
	var internalCertManagement bool
	var webhookNamespace string
	var webhookServiceName string
	var webhookConfigurationName string
	var kubeConfigOverrides clientcmd.ConfigOverrides
	command := &cobra.Command{
		Use:   "sidecar-injector",
		Short: "Start the Kubernetes mutating webhook injecting Kyverno Authz Server sidecars into pod containers",
		RunE: func(cmd *cobra.Command, args []string) error {
			// setup signals aware context
			return signals.Do(context.Background(), func(ctx context.Context) error {
				if internalCertManagement && certFile == "" && keyFile == "" {
					kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
						clientcmd.NewDefaultClientConfigLoadingRules(),
						&kubeConfigOverrides,
					)
					config, err := kubeConfig.ClientConfig()
					if err != nil {
						return err
					}
					logger := ctrl.LoggerFrom(ctx).WithName("certmanager")
					certDir, caBundle, err := certmanager.BootstrapWebhookCerts(ctx, logger, config, webhookNamespace, webhookServiceName)
					if err != nil {
						return err
					}
					certFile = filepath.Join(certDir, "tls.crt")
					keyFile = filepath.Join(certDir, "tls.key")
					clientset, err := kubernetes.NewForConfig(config)
					if err != nil {
						return err
					}
					if err := certmanager.PatchMutatingWebhookConfigCA(ctx, clientset, webhookConfigurationName, caBundle); err != nil {
						ctrl.LoggerFrom(ctx).Info("unable to patch MutatingWebhookConfiguration", "name", webhookConfigurationName, "error", err)
					}
				}
				// load sidecar
				sidecar, err := sidecar.Load(configFile)
				if err != nil {
					return err
				}
				// create server
				http := mutation.NewSidecarInjectorServer(address, certFile, keyFile, sidecar)
				// run server
				return http.Run(ctx)
			})
		},
	}
	command.Flags().StringVar(&address, "address", ":9443", "Address to listen on")
	command.Flags().StringVar(&certFile, "cert-file", "", "File containing tls certificate")
	command.Flags().StringVar(&keyFile, "key-file", "", "File containing tls private key")
	command.Flags().StringVar(&configFile, "config-file", "", "File containing the sidecar config")
	command.Flags().BoolVar(&internalCertManagement, "internal-cert-management", true, "Enable Kyverno internal certificate management")
	command.Flags().StringVar(&webhookNamespace, "webhook-namespace", "kyverno", "Namespace where webhook service and secrets are created")
	command.Flags().StringVar(&webhookServiceName, "webhook-service-name", "kyverno-sidecar-injector", "Webhook service name used for TLS certificate generation")
	command.Flags().StringVar(&webhookConfigurationName, "webhook-configuration-name", "", "MutatingWebhookConfiguration name to patch with generated CA bundle")
	clientcmd.BindOverrideFlags(&kubeConfigOverrides, command.Flags(), clientcmd.RecommendedConfigOverrideFlags("kube-"))
	return command
}
