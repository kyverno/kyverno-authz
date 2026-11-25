package events

import (
	"fmt"
	"strings"
)

type ReportsFilter map[string]bool

func ParseReportsFilter(value string) (ReportsFilter, error) {
	filter := ReportsFilter{}
	for _, result := range strings.Split(value, ",") {
		result = strings.TrimSpace(result)
		switch result {
		case "pass", "fail", "error", "warn", "skip":
			filter[result] = true
		default:
			return nil, fmt.Errorf("invalid report result %q: expected a comma-separated list of pass,fail,error,warn,skip", result)
		}
	}
	return filter, nil
}

func (f ReportsFilter) allows(decision string) bool {
	if f == nil {
		return true
	}
	switch decision {
	case RequestAllowed:
		return f["pass"]
	case RequestDenied:
		return f["fail"]
	case RequestErrored:
		return f["error"]
	}
	return false
}
