package main

import (
	"fmt"
	"sync"
	"time"
)

type AddrStr string

type ServerSentEvent struct {
	Type  string
	Event string
	ID    string
	Data  []byte
}

type SSEMember struct {
	C      chan ServerSentEvent
	ticker *time.Ticker
}

type SSEChannel struct {
	clients   map[AddrStr]SSEMember
	clientsMu sync.Mutex
}

func NewSSEChannel() *SSEChannel {
	return &SSEChannel{
		clients: make(map[AddrStr]SSEMember),
	}
}

func (c *SSEChannel) Subscribe(addr AddrStr) {
	ch := make(chan ServerSentEvent, 16)
	m := SSEMember{
		ch,
		time.NewTicker(15 * time.Second),
	}

	c.clientsMu.Lock()
	c.clients[addr] = m
	c.clientsMu.Unlock()

	go func() {
		for range m.ticker.C {
			m.C <- ServerSentEvent{
				"",
				"",
				"",
				[]byte("heartbeat"),
			}
		}
	}()
}

func (c *SSEChannel) Member(addr AddrStr) SSEMember {
	c.clientsMu.Lock()
	defer c.clientsMu.Unlock()
	m := c.clients[addr]
	return m
}

func (c *SSEChannel) Broadcast(payload []byte) {
	c.clientsMu.Lock()
	defer c.clientsMu.Unlock()
	for _, m := range c.clients {
		// drop-on-full (best effort delivery)
		select {
		case m.C <- ServerSentEvent{
			Type:  "data",
			Event: "message",
			ID:    fmt.Sprintf("%d", time.Now().UnixMilli()), // or use atomic counter
			Data:  payload,
		}:
		// client was able to receive
		default:
			// client is backed up
		}
	}
}

func (c *SSEChannel) Unsubscribe(addr AddrStr) {
	c.clientsMu.Lock()
	defer c.clientsMu.Unlock()
	m := c.clients[addr]
	delete(c.clients, addr)

	// ticker must be stopped BEFORE closing channel
	m.ticker.Stop()
	close(m.C)
}
