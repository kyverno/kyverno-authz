package certmanager

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	certmgr "github.com/kyverno/pkg/certmanager"
	tlsmgr "github.com/kyverno/pkg/tls"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

// Setup starts Kyverno certmanager controller for a given service.
func Setup(ctx context.Context, logger logr.Logger, clientset kubernetes.Interface, namespace, serviceName string) error {

	tlsConfig := &tlsmgr.Config{
		ServiceName: serviceName,
		Namespace:   namespace,
	}

	secretClient := clientset.CoreV1().Secrets(namespace)
	renewer := tlsmgr.NewCertRenewer(
		logger,
		secretClient,
		tlsmgr.CertRenewalInterval,
		tlsmgr.CAValidityDuration,
		tlsmgr.TLSValidityDuration,
		"",
		tlsConfig,
	)

	informerFactory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		12*time.Hour,
		informers.WithNamespace(namespace),
	)
	secretInformer := informerFactory.Core().V1().Secrets()

	controller := certmgr.NewController(
		logger,
		secretInformer,
		secretInformer,
		renewer,
		tlsConfig,
	)

	informerFactory.Start(ctx.Done())
	informerFactory.WaitForCacheSync(ctx.Done())
	go controller.Run(ctx, certmgr.Workers)

	logger.Info(
		"webhook TLS certificate controller started",
		"namespace", namespace,
		"serviceName", serviceName,
		"caSecret", tlsmgr.GenerateRootCASecretName(tlsConfig),
		"tlsSecret", tlsmgr.GenerateTLSPairSecretName(tlsConfig),
	)
	return nil
}

func GetTLSPairSecretName(serviceName, namespace string) string {
	return tlsmgr.GenerateTLSPairSecretName(&tlsmgr.Config{
		ServiceName: serviceName,
		Namespace:   namespace,
	})
}

func GetRootCASecretName(serviceName, namespace string) string {
	return tlsmgr.GenerateRootCASecretName(&tlsmgr.Config{
		ServiceName: serviceName,
		Namespace:   namespace,
	})
}
