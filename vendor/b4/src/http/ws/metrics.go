// src/http/ws/metrics.go
package ws

import (
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/http/handler"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/metrics"
	"github.com/gorilla/websocket"
)

// HandleMetricsWebSocket handles WebSocket connections for real-time metrics
func HandleMetricsWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("Failed to upgrade metrics WebSocket: %v", err)
		return
	}
	defer conn.Close()

	log.Tracef("Metrics WebSocket client connected from %s", r.RemoteAddr)

	// Send metrics every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Send initial metrics immediately
	metrics := metrics.GetMetricsCollector().GetSnapshot()
	if err := conn.WriteJSON(metrics); err != nil {
		log.Errorf("Failed to send initial metrics: %v", err)
		return
	}

	// Keep connection alive with ping/pong
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Start a goroutine to read and handle pings
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// Send periodic updates
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ticker.C:
			metrics := handler.GetMetricsCollector().GetSnapshot()

			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(metrics); err != nil {
				log.Tracef("Metrics WebSocket client disconnected: %v", err)
				return
			}

		case <-pingTicker.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-done:
			return
		}
	}
}
