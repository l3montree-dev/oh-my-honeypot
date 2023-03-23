package transport

import (
	"fmt"
	"net/http"

	"golang.org/x/net/websocket"
)

type websocketTransport struct {
	msgs chan []byte
	port int
}

type WebsocketConfig struct {
	Port int
}

func (w *websocketTransport) handler(ws *websocket.Conn) {

}

func (w *websocketTransport) Listen() chan<- []byte {
	http.Handle("/ws", websocket.Handler(w.handler))
	go func() {
		err := http.ListenAndServe(":"+fmt.Sprintf("%d", w.port), nil)
		if err != nil {
			panic("ListenAndServe: " + err.Error())
		}
	}()
	return w.msgs
}

func NewWebsocketTransport(config WebsocketConfig) Transport {
	return &websocketTransport{
		msgs: make(chan []byte),
		port: config.Port,
	}
}
