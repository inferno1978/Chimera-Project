package ws

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestBroadcastWriter_LineBuffering(t *testing.T) {
	hub := &LogHub{
		clients: map[*logClient]struct{}{},
		in:      make(chan []byte, 100),
		reg:     make(chan *logClient),
		unreg:   make(chan *logClient),
		stop:    make(chan struct{}),
	}

	writer := &broadcastWriter{h: hub}

	t.Run("complete line sends immediately", func(t *testing.T) {
		// Drain any existing messages
		for len(hub.in) > 0 {
			<-hub.in
		}

		n, err := writer.Write([]byte("hello world\n"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != 12 {
			t.Errorf("expected 12 bytes written, got %d", n)
		}

		select {
		case msg := <-hub.in:
			if string(msg) != "hello world" {
				t.Errorf("expected 'hello world', got '%s'", string(msg))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("expected message to be sent")
		}
	})

	t.Run("partial line buffers until newline", func(t *testing.T) {
		for len(hub.in) > 0 {
			<-hub.in
		}
		writer.buf = nil

		writer.Write([]byte("partial"))

		select {
		case <-hub.in:
			t.Error("partial line should not send")
		case <-time.After(50 * time.Millisecond):
			// expected
		}

		writer.Write([]byte(" complete\n"))

		select {
		case msg := <-hub.in:
			if string(msg) != "partial complete" {
				t.Errorf("expected 'partial complete', got '%s'", string(msg))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("expected message after newline")
		}
	})

	t.Run("multiple lines in single write", func(t *testing.T) {
		for len(hub.in) > 0 {
			<-hub.in
		}
		writer.buf = nil

		writer.Write([]byte("line1\nline2\nline3\n"))

		var received []string
		timeout := time.After(100 * time.Millisecond)
	loop:
		for {
			select {
			case msg := <-hub.in:
				received = append(received, string(msg))
			case <-timeout:
				break loop
			}
		}

		if len(received) != 3 {
			t.Errorf("expected 3 lines, got %d: %v", len(received), received)
		}
	})

	t.Run("preserves trailing partial", func(t *testing.T) {
		for len(hub.in) > 0 {
			<-hub.in
		}
		writer.buf = nil

		writer.Write([]byte("complete\npartial"))

		select {
		case msg := <-hub.in:
			if string(msg) != "complete" {
				t.Errorf("expected 'complete', got '%s'", string(msg))
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("expected first line")
		}

		// Should have buffered "partial"
		if string(writer.buf) != "partial" {
			t.Errorf("expected 'partial' in buffer, got '%s'", string(writer.buf))
		}
	})
}

func TestLogHub_ClientRegistration(t *testing.T) {
	hub := &LogHub{
		clients: map[*logClient]struct{}{},
		in:      make(chan []byte, 100),
		reg:     make(chan *logClient),
		unreg:   make(chan *logClient),
		stop:    make(chan struct{}),
	}

	go hub.run()
	defer hub.Stop()

	t.Run("register client", func(t *testing.T) {
		client := &logClient{send: make(chan []byte, 10)}
		hub.reg <- client

		time.Sleep(50 * time.Millisecond)

		hub.mu.RLock()
		_, exists := hub.clients[client]
		hub.mu.RUnlock()

		if !exists {
			t.Error("client should be registered")
		}
	})

	t.Run("unregister client", func(t *testing.T) {
		client := &logClient{send: make(chan []byte, 10)}
		hub.reg <- client
		time.Sleep(50 * time.Millisecond)

		hub.unreg <- client
		time.Sleep(50 * time.Millisecond)

		hub.mu.RLock()
		_, exists := hub.clients[client]
		hub.mu.RUnlock()

		if exists {
			t.Error("client should be unregistered")
		}
	})
}

func TestLogHub_MessageBroadcast(t *testing.T) {
	hub := &LogHub{
		clients: map[*logClient]struct{}{},
		in:      make(chan []byte, 100),
		reg:     make(chan *logClient),
		unreg:   make(chan *logClient),
		stop:    make(chan struct{}),
	}

	go hub.run()
	defer hub.Stop()

	t.Run("broadcasts to all clients", func(t *testing.T) {
		client1 := &logClient{send: make(chan []byte, 10)}
		client2 := &logClient{send: make(chan []byte, 10)}

		hub.reg <- client1
		hub.reg <- client2
		time.Sleep(50 * time.Millisecond)

		hub.in <- []byte("test message")

		timeout := time.After(100 * time.Millisecond)

		select {
		case msg := <-client1.send:
			if string(msg) != "test message" {
				t.Errorf("client1: expected 'test message', got '%s'", string(msg))
			}
		case <-timeout:
			t.Error("client1 should receive message")
		}

		select {
		case msg := <-client2.send:
			if string(msg) != "test message" {
				t.Errorf("client2: expected 'test message', got '%s'", string(msg))
			}
		case <-timeout:
			t.Error("client2 should receive message")
		}
	})

	t.Run("skips client with full buffer", func(t *testing.T) {
		// Client with buffer size 1
		slowClient := &logClient{send: make(chan []byte, 1)}
		fastClient := &logClient{send: make(chan []byte, 10)}

		hub.reg <- slowClient
		hub.reg <- fastClient
		time.Sleep(50 * time.Millisecond)

		// Fill slow client's buffer
		slowClient.send <- []byte("blocker")

		// Send message - should skip slow client, reach fast client
		hub.in <- []byte("new message")
		time.Sleep(50 * time.Millisecond)

		select {
		case msg := <-fastClient.send:
			if string(msg) != "new message" {
				t.Errorf("expected 'new message', got '%s'", string(msg))
			}
		default:
			t.Error("fast client should receive message")
		}

		// Slow client should only have the blocker
		select {
		case msg := <-slowClient.send:
			if string(msg) != "blocker" {
				t.Errorf("expected 'blocker', got '%s'", string(msg))
			}
		default:
			t.Error("slow client should have blocker")
		}

		select {
		case <-slowClient.send:
			t.Error("slow client should not have new message")
		default:
			// expected
		}
	})
}

func TestLogHub_Stop(t *testing.T) {
	hub := &LogHub{
		clients: map[*logClient]struct{}{},
		in:      make(chan []byte, 100),
		reg:     make(chan *logClient),
		unreg:   make(chan *logClient),
		stop:    make(chan struct{}),
	}

	go hub.run()

	client := &logClient{send: make(chan []byte, 10)}
	hub.reg <- client
	time.Sleep(50 * time.Millisecond)

	hub.Stop()
	time.Sleep(50 * time.Millisecond)

	// Client's send channel should be closed
	_, ok := <-client.send
	if ok {
		t.Error("client send channel should be closed after hub stop")
	}

	// Double stop should not panic
	hub.Stop()
}

func TestLogHub_Concurrent(t *testing.T) {
	hub := &LogHub{
		clients: map[*logClient]struct{}{},
		in:      make(chan []byte, 1000),
		reg:     make(chan *logClient, 100),
		unreg:   make(chan *logClient, 100),
		stop:    make(chan struct{}),
	}

	go hub.run()
	defer hub.Stop()

	var wg sync.WaitGroup
	clients := make([]*logClient, 10)

	// Register clients concurrently
	for i := 0; i < 10; i++ {
		clients[i] = &logClient{send: make(chan []byte, 100)}
		wg.Add(1)
		go func(c *logClient) {
			defer wg.Done()
			hub.reg <- c
		}(clients[i])
	}
	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	// Send messages concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			hub.in <- []byte("msg")
		}(i)
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	// Each client should have received messages
	for i, c := range clients {
		count := len(c.send)
		if count == 0 {
			t.Errorf("client %d received no messages", i)
		}
	}
}

func TestUpgrader_CheckOrigin(t *testing.T) {
	// CheckOrigin should allow all origins (returns true)
	if !Upgrader.CheckOrigin(nil) {
		t.Error("Upgrader.CheckOrigin should return true for any request")
	}
}

func TestLogWriter_ReturnsSameInstance(t *testing.T) {
	// Reset for test isolation
	logWriter = nil
	logHub = nil
	logOnce = sync.Once{}

	w1 := LogWriter()
	w2 := LogWriter()

	if w1 != w2 {
		t.Error("LogWriter should return the same instance")
	}
}

func TestBroadcastWriter_EmptyWrite(t *testing.T) {
	hub := &LogHub{
		clients: map[*logClient]struct{}{},
		in:      make(chan []byte, 100),
		reg:     make(chan *logClient),
		unreg:   make(chan *logClient),
		stop:    make(chan struct{}),
	}

	writer := &broadcastWriter{h: hub}

	n, err := writer.Write([]byte{})
	if err != nil {
		t.Errorf("empty write should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes, got %d", n)
	}
}

func TestBroadcastWriter_OnlyNewlines(t *testing.T) {
	hub := &LogHub{
		clients: map[*logClient]struct{}{},
		in:      make(chan []byte, 100),
		reg:     make(chan *logClient),
		unreg:   make(chan *logClient),
		stop:    make(chan struct{}),
	}

	writer := &broadcastWriter{h: hub}
	writer.buf = nil

	writer.Write([]byte("\n\n\n"))

	// Should send 3 empty lines
	count := 0
	timeout := time.After(100 * time.Millisecond)
loop:
	for {
		select {
		case msg := <-hub.in:
			if len(msg) != 0 {
				t.Errorf("expected empty line, got '%s'", string(msg))
			}
			count++
		case <-timeout:
			break loop
		}
	}

	if count != 3 {
		t.Errorf("expected 3 empty lines, got %d", count)
	}
}

func BenchmarkBroadcastWriter(b *testing.B) {
	hub := &LogHub{
		clients: map[*logClient]struct{}{},
		in:      make(chan []byte, 10000),
		reg:     make(chan *logClient),
		unreg:   make(chan *logClient),
		stop:    make(chan struct{}),
	}

	go hub.run()
	defer hub.Stop()

	writer := &broadcastWriter{h: hub}
	line := bytes.Repeat([]byte("x"), 100)
	line = append(line, '\n')

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		writer.Write(line)
	}
}
