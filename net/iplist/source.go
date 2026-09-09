package iplist

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultRefreshInterval = time.Hour + 57*time.Minute + 13*time.Second

type SourceConfig struct {
	Source          string
	CacheDir        string
	HTTPClient      *http.Client
	RefreshInterval time.Duration
	Optional        bool
	OnRefresh       func(SourceEvent)
}

type SourceEvent struct {
	Entries uint64
	Err     error
}

type sourceSnapshot struct {
	entries []string
}

type Source struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     SourceConfig
	current    atomic.Pointer[sourceSnapshot]
	observers  []func(SourceEvent)
	observerMu sync.RWMutex
}

func NewSource(ctx context.Context, config SourceConfig) (*Source, error) {
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = DefaultRefreshInterval
	}
	sourceCtx, cancel := context.WithCancel(ctx)
	s := &Source{ctx: sourceCtx, cancel: cancel, config: config}
	entries, err := s.load()
	if err != nil {
		cancel()
		return nil, err
	}
	s.store(entries)
	go s.refreshLoop()
	return s, nil
}

func (s *Source) Entries() []string {
	current := s.current.Load()
	if current == nil {
		return nil
	}
	return append([]string(nil), current.entries...)
}

func (s *Source) Refresh() error {
	entries, err := s.load()
	if err != nil {
		s.emit(SourceEvent{Entries: uint64(len(s.Entries())), Err: err})
		return err
	}
	s.store(entries)
	s.emit(SourceEvent{Entries: uint64(len(entries))})
	return nil
}

func (s *Source) Subscribe(observer func(SourceEvent)) {
	if observer == nil {
		return
	}
	s.observerMu.Lock()
	s.observers = append(s.observers, observer)
	s.observerMu.Unlock()
}

func (s *Source) emit(event SourceEvent) {
	if s.config.OnRefresh != nil {
		s.config.OnRefresh(event)
	}
	s.observerMu.RLock()
	observers := append([]func(SourceEvent){}, s.observers...)
	s.observerMu.RUnlock()
	for _, observer := range observers {
		observer(event)
	}
}

func (s *Source) Close() error {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Source) load() ([]string, error) {
	if s.config.Source == "" {
		if s.config.Optional {
			return nil, nil
		}
		return nil, errors.New("source is required")
	}
	if s.config.Optional {
		parsed, parseErr := url.Parse(s.config.Source)
		isURL := parseErr == nil && (parsed.Scheme == "http" || parsed.Scheme == "https")
		if !isURL {
			if _, err := os.Stat(s.config.Source); os.IsNotExist(err) {
				return nil, nil
			} else if err != nil {
				return nil, err
			}
		}
	}
	return Load(s.ctx, s.config.Source, s.config.CacheDir, s.config.HTTPClient)
}

func (s *Source) store(entries []string) {
	copyEntries := append([]string(nil), entries...)
	s.current.Store(&sourceSnapshot{entries: copyEntries})
}

func (s *Source) refreshLoop() {
	ticker := time.NewTicker(s.config.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			_ = s.Refresh()
		}
	}
}
