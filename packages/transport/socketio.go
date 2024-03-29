package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	socketio "github.com/googollee/go-socket.io"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
)

type socketioTransport struct {
	msgs chan set.Token
	port int
}

type SocketIOConfig struct {
	Port int
}

func (w *socketioTransport) Listen() chan<- set.Token {
	server := socketio.NewServer(nil)

	server.OnConnect("/", func(s socketio.Conn) error {
		s.SetContext("")
		fmt.Println("connected:", s.ID())
		return nil
	})

	go server.Serve()

	server.BroadcastToRoom("", "bcast", "attack")
	http.Handle("/socket.io/", server)
	go func() {
		log.Println("Socket.io transport listening on port", w.port)
		err := http.ListenAndServe(":"+fmt.Sprintf("%d", w.port), nil)
		if err != nil {
			panic("ListenAndServe: " + err.Error())
		}
	}()

	// listen to all tokens passed into the channel
	go func() {
		for msg := range w.msgs {
			// marshal the token to json
			// and send it to the socket
			bytes, err := json.Marshal(msg)
			if err != nil {
				log.Println("Error marshalling token to json:", err)
				continue
			}
			server.BroadcastToRoom("", "bcast", "attack", string(bytes))
		}
	}()

	return w.msgs
}

func NewSocketIO(config SocketIOConfig) Transport {
	return &socketioTransport{
		msgs: make(chan set.Token),
		port: config.Port,
	}
}
