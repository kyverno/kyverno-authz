package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/go-logr/logr"
)

type writerEventSubscriber[Req any] struct {
	logger    logr.Logger
	msgFormat string
	writer    io.Writer
}

// ammar: also provide the option for file writing
func NewWriterEventSubscriber[Req any](w io.Writer, l logr.Logger, msgFormat string) EventIface[Req] {
	return &writerEventSubscriber[Req]{
		writer: w,
		logger: l,
	}
}

func (s *writerEventSubscriber[Req]) Push(_ context.Context, t time.Time, req Req, res ResultAccessor) {
	jsonStr, err := json.Marshal(req)
	if err != nil {
		s.logger.Error(err, "error unmarshalling request")
		return
	}
	result, resultErr := res.MustGet()
	// if the result is an error we will print in the result log placeholder ResultErrored: <the_actual_error>
	if resultErr != nil {
		fmt.Fprintf(s.writer, s.msgFormat, t, jsonStr, fmt.Sprintf("%s: %s", result, resultErr))
	} else {
		fmt.Fprintf(s.writer, s.msgFormat, t, jsonStr, result)
	}
}
