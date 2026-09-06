package ws

import (
	"net/http"

	"github.com/gorilla/websocket"
)

var Upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		//TODO: Allow connections from any origin - need to handle CORS  later
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}
