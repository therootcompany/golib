package csvdb

import "context"

// WriteGate permits one local file write at a time.
type WriteGate struct {
	slots chan struct{}
}

// NewWriteGate creates a gate that permits one write at a time.
func NewWriteGate() *WriteGate {
	return &WriteGate{slots: make(chan struct{}, 1)}
}

func (g *WriteGate) acquire(ctx context.Context) error {
	if g == nil {
		return nil
	}
	select {
	case g.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *WriteGate) release() {
	if g != nil {
		<-g.slots
	}
}

// DefaultGate is the shared write gate for the process.
var DefaultGate = NewWriteGate()
