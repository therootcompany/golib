package csvx

import (
	"errors"
	"io"
	"testing"

	"github.com/jszwec/csvutil"
)

// scriptedReader is a csvutil.Reader that replays a fixed sequence of
// records one Read at a time, then io.EOF.
type scriptedReader struct {
	records [][]string
	i       int
}

func (s *scriptedReader) Read() ([]string, error) {
	if s.i >= len(s.records) {
		return nil, io.EOF
	}
	rec := s.records[s.i]
	s.i++
	return rec, nil
}

// skipBlanks must skip blank records and pass through non-blank ones in
// order, consuming source records lazily.
func TestSkipBlanksStreaming(t *testing.T) {
	w := skipBlanks{in: &scriptedReader{records: [][]string{
		{"", ""}, // blank, skipped
		{"a", "b"},
		{" ", ""}, // whitespace-only, skipped
		{"1", "x"},
		{"2", "y"},
	}}}

	for _, want := range [][]string{{"a", "b"}, {"1", "x"}, {"2", "y"}} {
		got, err := w.Read()
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("record = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("record = %v, want %v", got, want)
			}
		}
	}
	if _, err := w.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("final Read err = %v, want io.EOF", err)
	}
}

// A non-EOF error from the wrapped reader must propagate untouched, even
// when reached while skipping blanks.
func TestSkipBlanksPropagatesError(t *testing.T) {
	boom := errors.New("boom")
	// First read: one blank record. Second read: boom.
	in := &errAfter{in: &scriptedReader{records: [][]string{{""}}}, after: 1, boom: boom}
	w := skipBlanks{in: in}

	if _, err := w.Read(); err != boom {
		t.Fatalf("Read err = %v, want boom", err)
	}
}

// errAfter passes reads through until n of them have happened, then a
// fixed error.
type errAfter struct {
	in    csvutil.Reader
	after int
	n     int
	boom  error
}

func (e *errAfter) Read() ([]string, error) {
	e.n++
	if e.n > e.after {
		return nil, e.boom
	}
	return e.in.Read()
}
