package ws

import "sync"

type LogHub struct {
	mu      sync.RWMutex
	clients map[*logClient]struct{}
	in      chan []byte
	reg     chan *logClient
	unreg   chan *logClient
	stop    chan struct{}
}
