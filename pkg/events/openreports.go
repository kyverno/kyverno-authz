package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	openreportsclient "github.com/openreports/reports-api/pkg/client/clientset/versioned/typed/openreports.io/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type openreportsEventSubscriber[Req any] struct {
	results       *ringBuffer[openreportsv1alpha1.ReportResult]
	client        openreportsclient.OpenreportsV1alpha1Interface
	allowed       int
	denied        int
	errored       int
	namespace     string
	reportName    string
	msgFormat     string
	logger        logr.Logger
	flushInterval *time.Duration
}

func NewOpenreportsSubscriber[Req any](bufferSize int,
	orClient openreportsclient.OpenreportsV1alpha1Interface,
	flushInterval *time.Duration,
	logger logr.Logger,
	reportName, ns, msgFormat string) EventIface[Req] {
	o := &openreportsEventSubscriber[Req]{
		client:     orClient,
		results:    NewRingBuffer[openreportsv1alpha1.ReportResult](bufferSize),
		namespace:  ns,
		reportName: reportName,
		msgFormat:  msgFormat,
	}
	if flushInterval != nil {
		o.flushInterval = flushInterval
		go o.flushResultsToReport(context.Background())
	}
	return o
}

// ammar: should we also convey the policy that caused the decision ?
func (o *openreportsEventSubscriber[Req]) Push(ctx context.Context, t time.Time, req Req, res ResultAccessor) {
	reportResult, err := o.newReportResult(t, req, res)
	if err != nil {
		o.logger.Error(err, "error building report result")
		return
	}

	o.results.Push(*reportResult)

	// the new report result already did the aggregation and we will handle pushing the report
	// when the interval is elapsed
	if o.flushInterval != nil {
		return
	}

	o.pushReport(ctx)
}

func (o *openreportsEventSubscriber[Req]) newReportResult(t time.Time, r Req, resultAccessor ResultAccessor) (*openreportsv1alpha1.ReportResult, error) {
	reportResult := &openreportsv1alpha1.ReportResult{}
	// ammar: is there a constant provided in the openreports package ?
	// ammar: we should also have request skipped if it didn't match the conditions
	res, resultErr := resultAccessor.MustGet()

	switch res {
	case RequestAllowed:
		reportResult.Result = openreportsv1alpha1.Result("pass")
		o.allowed++
	case RequestDenied:
		reportResult.Result = openreportsv1alpha1.Result("fail")
		o.denied++
	case RequestErrored:
		reportResult.Result = openreportsv1alpha1.Result("error")
		o.errored++
	}
	reportResult.Timestamp = metav1.Timestamp{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
	jsonStr, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	var resultStr string
	if resultErr != nil {
		resultStr = fmt.Sprintf("%v: %v", res, resultErr)
	} else {
		resultStr = fmt.Sprintf("%v", res)
	}

	reportResult.Description = fmt.Sprintf(o.msgFormat,
		t.Format(time.RFC3339),
		string(jsonStr),
		resultStr,
	)
	return reportResult, nil
}

//lint:ignore SA5008 reason
func (o *openreportsEventSubscriber[Req]) newReport() *openreportsv1alpha1.Report {
	return &openreportsv1alpha1.Report{
		ObjectMeta: metav1.ObjectMeta{
			Name:      o.reportName,
			Namespace: o.namespace,
		},
		Summary: openreportsv1alpha1.ReportSummary{
			Error: o.errored,
			Pass:  o.allowed,
			Fail:  o.denied,
		},
		Results: o.results.Values(),
	}
}

func (o *openreportsEventSubscriber[Req]) pushReport(ctx context.Context) {
	rep, err := o.client.Reports(o.namespace).Get(ctx, o.reportName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// create it
			rep = o.newReport()
			_, err := o.client.Reports(o.namespace).Create(ctx, rep, metav1.CreateOptions{})
			if err != nil {
				o.logger.Error(err, "error creating report")
			}
			return
		}

		// error isn't the not found error. meaning that its a legitimate error
		o.logger.Error(err, "error fetching report")
		return
	}

	// its already there, update it
	// update the results in the report to be whats in the ring buffer
	rep.Results = o.results.Values()

	// update the report summary
	rep.Summary.Error = o.errored
	rep.Summary.Pass = o.allowed
	rep.Summary.Fail = o.denied

	_, err = o.client.Reports(o.namespace).Update(ctx, rep, metav1.UpdateOptions{})
	if err != nil {
		o.logger.Error(err, "error updating report with results")
		return
	}
}

// TODO: handle context cancellation
func (o *openreportsEventSubscriber[Req]) flushResultsToReport(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(*o.flushInterval):
			o.pushReport(ctx)
		}
	}
}
