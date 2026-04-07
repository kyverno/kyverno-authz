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
	eventChan chan event[Req]
}

// pass a context to the constructor to make it the context used to cancel the event loop
func NewK8sEventSubscriber[Req any](ctx context.Context, client kubernetes.Interface, ns string, logger logr.Logger, msgFormat string) EventIface[Req] {
	eventChan := make(chan event[Req], 10)
	k := &k8sEventSubscriber[Req]{
		client:    client,
		namespace: ns,
		logger:    logger,
		msgFormat: msgFormat,
		eventChan: eventChan,
	}
	go k.eventLoop(ctx)
	return k
}

func (k *k8sEventSubscriber[Req]) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			k.logger.Info("k8s event handler exiting")
			return
		case ev := <-k.eventChan:
			jsonReq, err := json.Marshal(ev.req)
			if err != nil {
				k.logger.Error(err, "error marshalling request to json for event")
				continue
			}

			result, resultErr := ev.res.MustGet()

			var resultStr string
			if resultErr != nil {
				resultStr = fmt.Sprintf("%v: %v", result, resultErr)
			} else {
				resultStr = fmt.Sprintf("%v", result)
			}

			eventMsg := fmt.Sprintf(k.msgFormat,
				ev.t.Format(time.RFC3339),
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
				EventTime:           metav1.NewMicroTime(ev.t),
				FirstTimestamp:      metav1.NewTime(ev.t),
				LastTimestamp:       metav1.NewTime(ev.t),
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
	}
}

func (k *k8sEventSubscriber[Req]) Push(ctx context.Context, t time.Time, req Req, res ResultAccessor) {
	event := event[Req]{
		t:   t,
		req: req,
		res: res,
	}

	// try to push the event, drop it if the channel is full
	select {
	case k.eventChan <- event:
	default:
		k.logger.Error(nil, "event channel full, dropping event")
	}
}
