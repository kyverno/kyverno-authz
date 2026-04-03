package certmanager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	webhookCertWaitInterval = 500 * time.Millisecond
	webhookCertWaitTimeout  = 60 * time.Second
)

// BootstrapWebhookCerts starts the internal cert manager, waits for TLS secrets,
// writes tls.crt/tls.key in a temporary cert dir, and returns cert dir and CA bundle.
func BootstrapWebhookCerts(ctx context.Context, logger logr.Logger, config *rest.Config, namespace, serviceName string) (certDir string, caBundle []byte, err error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", nil, err
	}

	if err := Setup(ctx, logger, config, namespace, serviceName); err != nil {
		return "", nil, err
	}

	tlsSecretName := GetTLSPairSecretName(serviceName, namespace)
	caSecretName := GetRootCASecretName(serviceName, namespace)
	secretClient := clientset.CoreV1().Secrets(namespace)

	deadline := time.Now().Add(webhookCertWaitTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		default:
		}

		tlsSecret, err := secretClient.Get(ctx, tlsSecretName, metav1.GetOptions{})
		if err == nil && tlsSecret != nil && len(tlsSecret.Data[corev1.TLSCertKey]) > 0 && len(tlsSecret.Data[corev1.TLSPrivateKeyKey]) > 0 {
			certDir, err = os.MkdirTemp("", "kyverno-authz-webhook-certs-")
			if err != nil {
				return "", nil, err
			}
			if err := os.WriteFile(filepath.Join(certDir, "tls.crt"), tlsSecret.Data[corev1.TLSCertKey], 0o600); err != nil {
				_ = os.RemoveAll(certDir)
				return "", nil, err
			}
			if err := os.WriteFile(filepath.Join(certDir, "tls.key"), tlsSecret.Data[corev1.TLSPrivateKeyKey], 0o600); err != nil {
				_ = os.RemoveAll(certDir)
				return "", nil, err
			}

			caSecret, err := secretClient.Get(ctx, caSecretName, metav1.GetOptions{})
			if err != nil {
				_ = os.RemoveAll(certDir)
				return "", nil, err
			}
			caBundle = caSecret.Data[corev1.TLSCertKey]
			if len(caBundle) == 0 {
				caBundle = caSecret.Data["rootCA.crt"]
			}
			if len(caBundle) == 0 {
				_ = os.RemoveAll(certDir)
				return "", nil, fmt.Errorf("CA secret %s/%s has no tls.crt or rootCA.crt", namespace, caSecretName)
			}

			logger.Info("webhook TLS certs ready", "certDir", certDir, "tlsSecret", tlsSecretName)
			return certDir, caBundle, nil
		}
		time.Sleep(webhookCertWaitInterval)
	}

	return "", nil, fmt.Errorf("timed out waiting for webhook TLS secret %s/%s", namespace, tlsSecretName)
}

func PatchValidatingWebhookConfigCA(ctx context.Context, clientset *kubernetes.Clientset, vwcName string, caBundle []byte) error {
	if vwcName == "" || len(caBundle) == 0 {
		return nil
	}
	client := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	config, err := client.Get(ctx, vwcName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	for i := range config.Webhooks {
		config.Webhooks[i].ClientConfig.CABundle = caBundle
	}
	_, err = client.Update(ctx, config, metav1.UpdateOptions{})
	return err
}

func PatchMutatingWebhookConfigCA(ctx context.Context, clientset *kubernetes.Clientset, mwcName string, caBundle []byte) error {
	if mwcName == "" || len(caBundle) == 0 {
		return nil
	}
	client := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
	config, err := client.Get(ctx, mwcName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	for i := range config.Webhooks {
		config.Webhooks[i].ClientConfig.CABundle = caBundle
	}
	_, err = client.Update(ctx, config, metav1.UpdateOptions{})
	return err
}

func CABundlePatch(webhooks []admissionregistrationv1.ValidatingWebhook, caBundle []byte) []admissionregistrationv1.ValidatingWebhook {
	for i := range webhooks {
		webhooks[i].ClientConfig.CABundle = caBundle
	}
	return webhooks
}
