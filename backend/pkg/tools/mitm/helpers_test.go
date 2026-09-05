package mitm

import (
	"context"
	"testing"
)

// withTestContext returns a live context for the test lifetime.
func withTestContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}
