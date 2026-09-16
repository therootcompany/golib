// Package csvdb provides a generic CSV/TSV database adapter.
// Store implements both rowsync.Fetcher and rowsync.Updater over a file
// in an os.Root directory, with atomic writes and optional normalization.
package csvdb

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/therootcompany/golib/database/rowsync"

	"github.com/jszwec/csvutil"

	"github.com/therootcompany/golib/database/csvx"
)

// Store is a generic TSV/CSV file storage adapter backed by an os.Root.
// Root must be non-nil; Name is the file within the root directory.
type Store[T any] struct {
	Root      *os.Root
	Name      string
	Format    string
	Gate      *WriteGate
	Normalize func([]T)
}

var _ rowsync.Fetcher[struct{}] = (*Store[struct{}])(nil)
var _ rowsync.Updater[struct{}] = (*Store[struct{}])(nil)

// errHeaderMismatch signals that the existing file's header doesn't match
// the encoder's header. Update falls back to a full atomic rewrite.
var errHeaderMismatch = errors.New("tsv: existing file header does not match encoded header")

// Init validates the root and file name.
// Combined fetches from several stores and concatenates their rows, e.g.
// clients.tsv + redirects.tsv, which share one row type and one target.
type Combined[T any] struct {
	Stores []rowsync.Fetcher[T]
}

func (c *Combined[T]) Init(_ context.Context) ([]rowsync.Message, error) {
	if c == nil || len(c.Stores) == 0 {
		return nil, errors.New("at least one store is required")
	}
	var messages []rowsync.Message
	for _, s := range c.Stores {
		msgs, err := s.Init(context.Background())
		if err != nil {
			return nil, err
		}
		messages = append(messages, msgs...)
	}
	return messages, nil
}

func (c *Combined[T]) Fetch(ctx context.Context) ([]T, error) {
	if c == nil || len(c.Stores) == 0 {
		return nil, errors.New("at least one store is required")
	}
	var rows []T
	for _, s := range c.Stores {
		part, err := s.Fetch(ctx)
		if err != nil {
			return nil, err
		}
		rows = append(rows, part...)
	}
	return rows, nil
}

func (s *Store[T]) Init(_ context.Context) ([]rowsync.Message, error) {
	if s == nil || s.Root == nil || strings.TrimSpace(s.Name) == "" {
		return nil, errors.New("root and name are required")
	}
	return []rowsync.Message{{String: s.Name, Type: "debug"}}, nil
}

// Fetch reads the existing file. Missing files return empty state.
func (s *Store[T]) Fetch(_ context.Context) ([]T, error) {
	if s == nil || s.Root == nil || strings.TrimSpace(s.Name) == "" {
		return nil, errors.New("root and name are required")
	}
	info, err := s.Root.Stat(s.Name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Size() == 0 {
		return nil, nil
	}
	file, err := s.Root.Open(s.Name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	rows, err := parseFile[T](file, s.format())
	if err != nil {
		return nil, err
	}
	if s.Normalize != nil {
		s.Normalize(rows)
	}
	return rows, nil
}

// Update applies a plan to the file. It serializes Plan.Final, never raw
// source rows: UpdateMode plans keep destination-only rows, SyncMode plans
// drop them. A plan with no actions leaves the file untouched. Insert-only
// plans append without rewriting the existing snapshot; any update or delete
// takes the atomic replacement path. The previous file survives encoding or
// rename failures (temp file + rename, no fsync).
func (s *Store[T]) Update(ctx context.Context, plan rowsync.Plan[T]) error {
	if s == nil || s.Root == nil || strings.TrimSpace(s.Name) == "" {
		return errors.New("root and name are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(plan.Actions) == 0 {
		return nil
	}
	gate := s.Gate
	if gate == nil {
		gate = DefaultGate
	}
	if err := gate.acquire(ctx); err != nil {
		return err
	}
	defer gate.release()

	// Insert-only plans can append without rewriting the existing snapshot.
	// If the existing file's header doesn't match the encoder's header (e.g.
	// the file was manually created from a template with different columns),
	// fall through to the atomic replacement path so the whole file is
	// rewritten with a consistent header.
	inserts := make([]T, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		if action.Kind != rowsync.InsertAction {
			break
		}
		inserts = append(inserts, *action.After)
	}
	if len(inserts) == len(plan.Actions) {
		added := append([]T(nil), inserts...)
		if s.Normalize != nil {
			s.Normalize(added)
		}
		if err := s.appendFile(added); err == nil {
			return nil
		}
		// Header mismatch or read error — fall through to full rewrite.
	}
	if plan.Final == nil {
		return errors.New("plan final state is required for update or delete actions")
	}
	final := append([]T(nil), plan.Final...)
	if s.Normalize != nil {
		s.Normalize(final)
	}
	return AtomicWrite(s.Root, s.Name, func(tmp *os.File) error {
		return writeFile[T](tmp, final, s.format())
	})
}

// WriteAll replaces the file with rows, unconditionally. Use it for
// full-state writes that are not driven by a plan (split files, fetched
// config snapshots).
func (s *Store[T]) WriteAll(ctx context.Context, rows []T) error {
	if s == nil || s.Root == nil || strings.TrimSpace(s.Name) == "" {
		return errors.New("root and name are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	gate := s.Gate
	if gate == nil {
		gate = DefaultGate
	}
	if err := gate.acquire(ctx); err != nil {
		return err
	}
	defer gate.release()
	current := append([]T(nil), rows...)
	if s.Normalize != nil {
		s.Normalize(current)
	}
	return AtomicWrite(s.Root, s.Name, func(tmp *os.File) error {
		return writeFile[T](tmp, current, s.format())
	})
}

func (s *Store[T]) appendFile(items []T) error {
	if len(items) == 0 {
		return nil
	}
	var encoded bytes.Buffer
	if err := writeFile(&encoded, items, s.format()); err != nil {
		return err
	}
	data := encoded.Bytes()
	encodedHeader := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		encodedHeader = data[:i]
	}
	if info, err := s.Root.Stat(s.Name); err == nil && info.Size() > 0 {
		existing, err := s.Root.Open(s.Name)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(existing)
		var existingHeader []byte
		if scanner.Scan() {
			existingHeader = scanner.Bytes()
		}
		_ = existing.Close()
		if !bytes.Equal(existingHeader, encodedHeader) {
			return errHeaderMismatch
		}
		newline := bytes.IndexByte(data, '\n')
		if newline < 0 || newline+1 >= len(data) {
			return errors.New("append TSV: encoded rows have no data record")
		}
		data = data[newline+1:]
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := s.Root.OpenFile(s.Name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	writer := bufio.NewWriter(file)
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Flush()
}

func (s *Store[T]) format() string {
	if strings.TrimSpace(s.Format) != "" {
		return strings.ToLower(strings.TrimSpace(s.Format))
	}
	return detectFormat(s.Name)
}

func detectFormat(name string) string {
	switch ext := strings.ToLower(filepath.Ext(name)); ext {
	case ".tsv", ".tab":
		return "tsv"
	default:
		return "csv"
	}
}

func parseFile[T any](r io.Reader, format string) ([]T, error) {
	reader := csv.NewReader(r)
	reader.Comment = '#'
	if format == "tsv" {
		reader.Comma = '\t'
	}
	reader.FieldsPerRecord = -1
	dec, err := csvutil.NewDecoder(reader)
	if err != nil {
		return nil, err
	}
	dec.Tag = "json"
	dec.WithUnmarshalers(csvx.Unmarshalers())
	var items []T
	for {
		var item T
		if err := dec.Decode(&item); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func writeFile[T any](w io.Writer, items []T, format string) error {
	cw := csv.NewWriter(w)
	if format == "tsv" {
		cw.Comma = '\t'
	}
	enc := csvutil.NewEncoder(cw)
	enc.Tag = "json"
	enc.WithMarshalers(csvx.Marshalers())
	if err := enc.Encode(items); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}
