package csvx

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jszwec/csvutil"
)

// Parse parses records from an io.Reader in the requested format.
func Parse[T any](r io.Reader, format string) ([]T, error) {
	switch format {
	case "tab", "tsv":
		cr := csv.NewReader(r)
		cr.Comma = '\t'
		cr.FieldsPerRecord = -1
		return ParseCSV[T](cr)
	case "csv":
		cr := csv.NewReader(r)
		cr.Comma = ','
		cr.FieldsPerRecord = -1
		return ParseCSV[T](cr)
	case "json", "pretty":
		return ParseJSON[T](r)
	case "jsonl", "ndjson":
		return ParseJSONL[T](r)
	default:
		return nil, fmt.Errorf("unknown format: %s", format)
	}
}

// ParseCSV reads CSV/TSV from a csvutil Reader using csvutil streaming.
// The reader must already have its delimiter configured.
// Uses json struct tags and csvx marshalers for type handling.
//
// Blank records — rows where every cell is empty or whitespace-only —
// are skipped everywhere, including before the header. Human-maintained
// sources routinely carry stray blank lines (e.g. a Google Sheets export
// with an empty row above the header); without skipping, the first blank
// row would be taken as the header and every data row would decode to
// zero values. Skipping happens in a streaming reader wrapper: records
// are decoded one at a time and only one record is buffered at a time.
//
// A csv.Reader is a valid csvutil.Reader and can be passed directly.
func ParseCSV[T any](r csvutil.Reader) ([]T, error) {
	return parseDecoded[T](skipBlanks{in: r})
}

// skipBlanks is a streaming csvutil.Reader wrapper that drops blank
// records. It implements the csvutil.Reader interface (a single Read
// method) so *encoding/csv.Reader and other csvutil readers can be
// wrapped without concrete types.
type skipBlanks struct {
	in csvutil.Reader
}

func (s skipBlanks) Read() ([]string, error) {
	for {
		rec, err := s.in.Read()
		if err != nil {
			// io.EOF and other errors propagate; only blank
			// records (err == nil) are skipped.
			return rec, err
		}
		if !isBlankRecord(rec) {
			return rec, nil
		}
	}
}

// isBlankRecord reports whether every cell is empty or whitespace-only.
func isBlankRecord(rec []string) bool {
	for _, f := range rec {
		if strings.TrimSpace(f) != "" {
			return false
		}
	}
	return true
}

// parseDecoded runs the csvutil decode loop over a csvutil.Reader.
func parseDecoded[T any](r csvutil.Reader) ([]T, error) {
	dec, err := csvutil.NewDecoder(r)
	if err == io.EOF {
		// Empty stream (e.g. all-blank input): no header, no rows.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dec.Tag = "json"
	dec.WithUnmarshalers(Unmarshalers())

	var items []T
	for {
		var item T
		if err := dec.Decode(&item); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// ParseJSONWithEnvelope decodes a JSON envelope from r into T.
// T should be a struct with json tags matching the envelope fields
// (e.g. {"groups": [...], "kind": "...", "etag": "..."}).
// Returns zero value, nil on empty input (io.EOF on first decode).
func ParseJSONWithEnvelope[T any](r io.Reader) (T, error) {
	var resp T
	dec := json.NewDecoder(r)
	if err := dec.Decode(&resp); err != nil {
		if err == io.EOF {
			var zero T
			return zero, nil
		}
		var zero T
		return zero, fmt.Errorf("parse JSON envelope: %w", err)
	}
	return resp, nil
}

// ParseJSON decodes a JSON array [{…}, {…}] from r into a slice of T.
// Returns nil, nil on empty input (io.EOF on first decode).
func ParseJSON[T any](r io.Reader) ([]T, error) {
	var items []T
	dec := json.NewDecoder(r)
	if err := dec.Decode(&items); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	return items, nil
}

// ParseJSONL reads JSONL (one JSON object per line) from r into a slice of T.
// Each line is decoded independently; decoding stops at io.EOF.
func ParseJSONL[T any](r io.Reader) ([]T, error) {
	var items []T
	dec := json.NewDecoder(r)
	for {
		var item T
		if err := dec.Decode(&item); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode JSONL: %w", err)
		}
		items = append(items, item)
	}
	return items, nil
}

// Serialize writes values in the specified format.
func Serialize[T any](w io.Writer, values []T, format string) error {
	var comma = ','
	switch format {
	case "tab", "tsv":
		comma = '\t'
		fallthrough
	case "csv":
		cw := csv.NewWriter(w)
		cw.Comma = comma
		return SerializeCSV(cw, values)
	case "jsonl", "ndjson":
		enc := json.NewEncoder(w)
		return SerializeJSONL(enc, values)
	case "pretty":
		fallthrough
	case "json":
		enc := json.NewEncoder(w)
		if format == "pretty" {
			enc.SetIndent("", "  ")
		}
		if err := SerializeJSON(enc, values); err != nil {
			return err
		}
		_, err := w.Write([]byte("\n"))
		return err
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

// SerializeCSV writes items as CSV/TSV to a csv.Writer using json struct tags
// and csvx marshalers. The caller must have configured Comma (or left it at
// the default comma).
func SerializeCSV[T any](cw *csv.Writer, items []T) error {
	enc := csvutil.NewEncoder(cw)
	enc.Tag = "json"
	enc.WithMarshalers(Marshalers())
	if err := enc.Encode(items); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

// SerializeJSON writes items as a JSON array [{…}, {…}] using the provided
// json.Encoder.
func SerializeJSON[T any](enc *json.Encoder, items []T) error {
	if items == nil {
		items = []T{}
	}
	return enc.Encode(items)
}

// SerializeJSONL writes items as JSONL (one JSON object per line) using the
// provided json.Encoder.
func SerializeJSONL[T any](enc *json.Encoder, items []T) error {
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
}
