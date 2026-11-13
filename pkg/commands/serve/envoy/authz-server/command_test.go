package authzserver

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReportsFilterFlag(t *testing.T) {
	cmd := Command()
	require.Equal(t, "fail,error", cmd.Flags().Lookup("reports-filter").DefValue)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--reports-filter=unknown"})
	require.ErrorContains(t, cmd.Execute(), "invalid report result")
}
