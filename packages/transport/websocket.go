package transport

import (
	"fmt"
	"log"
	"net/http"

	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"golang.org/x/net/websocket"
)

type websocketTransport struct {
	msgs chan set.Token
	port int
}

type WebsocketConfig struct {
	Port int
}

func (w *websocketTransport) handler(ws *websocket.Conn) {

}

func (w *websocketTransport) Listen() chan<- set.Token {
	http.Handle("/ws", websocket.Handler(w.handler))
	go func() {
		log.Println("Websocket transport listening on port", w.port)
		err := http.ListenAndServe(":"+fmt.Sprintf("%d", w.port), nil)
		if err != nil {
			panic("ListenAndServe: " + err.Error())
		}
	}()
	return w.msgs
}

func NewWebsocket(config WebsocketConfig) Transport {
	return &websocketTransport{
		msgs: make(chan set.Token),
		port: config.Port,
	}
}
