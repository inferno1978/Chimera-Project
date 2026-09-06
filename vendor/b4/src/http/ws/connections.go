package ws

import (
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/log"
	"github.com/gorilla/websocket"
)

// HandleConnectionsWebSocket streams structured connection events from the
// log.ConnectionHub. New subscribers immediately receive a ring-buffer
// snapshot of recent events so the UI's connections page is populated even
// if it opens during an idle period.
func HandleConnectionsWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("Failed to upgrade connections WebSocket: %v", err)
		return
	}
	defer conn.Close()

	hub := log.GetConnectionHub()
	ch, snapshot := hub.Subscribe()
	defer hub.Unsubscribe(ch)

	for _, msg := range snapshot {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			return
		}
	}

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case msg := <-ch:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
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
