package events

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/go-logr/logr"
)

type writerEventSubscriber[Req any] struct {
	logger    logr.Logger
	msgFormat string
	writer    io.Writer
	redactor  *RequestRedactor
}

// ammar: also provide the option for file writing
// The redactor selects the request properties to write; a nil redactor records no headers.
func NewWriterEventSubscriber[Req any](w io.Writer, l logr.Logger, msgFormat string, redactor *RequestRedactor) EventIface[Req] {
	return &writerEventSubscriber[Req]{
		writer:    w,
		logger:    l,
		msgFormat: msgFormat,
		redactor:  redactor,
	}
}

func (s *writerEventSubscriber[Req]) Push(_ context.Context, t time.Time, req Req, res ResultAccessor) {
	// it's ok for the standard output writer to be synchronous
	result, resultErr := res.MustGet()

	// if the result is an error we will print in the result log placeholder ResultErrored: <the_actual_error>
	var resultStr string
	if resultErr != nil {
		resultStr = fmt.Sprintf("%v: %v", result, resultErr)
	} else {
		resultStr = fmt.Sprintf("%v", result)
	}

	_, err := fmt.Fprintf(s.writer, s.msgFormat,
		t.Format(time.RFC3339),
		s.redactor.JSON(req),
		resultStr,
	)
	if err != nil {
		s.logger.Error(err, "error writing decision log")
	}
}
