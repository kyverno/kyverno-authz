package events

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// all of these should be disabled by default in sidecar mode
type k8sEventSubscriber[Req any] struct {
	client kubernetes.Interface
	// namespace doesn't denote the namespace where the event happened since authz events
	// aren't really tied to a namespace, so this is just the namespace to log events to
	namespace string
	logger    logr.Logger
	msgFormat string
}

func NewK8sEventSubscriber[Req any](client kubernetes.Interface, ns string, logger logr.Logger, msgFormat string) EventIface[Req] {
	return &k8sEventSubscriber[Req]{
		client:    client,
		namespace: ns,
		logger:    logger,
		msgFormat: msgFormat,
	}
}

func (k *k8sEventSubscriber[Req]) Push(ctx context.Context, t time.Time, req Req, res ResultAccessor) {
	jsonReq, err := json.Marshal(req)
	if err != nil {
		k.logger.Error(err, "error marshalling request to json for event")
		return
	}

	result, resultErr := res.MustGet()

	var resultStr string
	if resultErr != nil {
		resultStr = fmt.Sprintf("%v: %v", result, resultErr)
	} else {
		resultStr = fmt.Sprintf("%v", result)
	}

	eventMsg := fmt.Sprintf(k.msgFormat,
		t.Format(time.RFC3339),
		string(jsonReq),
		resultStr,
	)

	eventName := strings.ReplaceAll(uuid.New().String(), "-", "")
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      eventName,
			Namespace: k.namespace,
		},
		Reason:              result,
		Message:             eventMsg,
		Type:                corev1.EventTypeNormal,
		EventTime:           metav1.NewMicroTime(t),
		FirstTimestamp:      metav1.NewTime(t),
		LastTimestamp:       metav1.NewTime(t),
		Count:               1,
		Action:              result,
		ReportingController: "kyverno-authz-server",
		ReportingInstance:   "kyverno-authz-server",
	}

	_, err = k.client.CoreV1().Events(k.namespace).Create(
		ctx,
		event,
		metav1.CreateOptions{},
	)

	if err != nil {
		k.logger.Error(err, "failed to push kubernetes event")
	}
}
