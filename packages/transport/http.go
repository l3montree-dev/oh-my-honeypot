package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"gitlab.com/neuland-homeland/honeypot/packages/store"
)

type HTTPConfig struct {
	Port  int
	Store store.Store[set.Token]
}

type httpTransport struct {
	port  int
	store store.Store[set.Token]
}

func (h *httpTransport) Listen() chan<- set.Token {
	// create a new http rest endpoint
	// that accepts a GET requests
	// and returns the messages
	listener := make(chan set.Token)
	go func() {
		for msg := range listener {
			h.store.Store(msg)
		}
	}()

	http.Handle("/messages", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			msgs := h.store.Get()
			arr, err := json.Marshal(msgs)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(200)
			w.Write(arr)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))

	go http.ListenAndServe(":"+fmt.Sprintf("%d", h.port), nil)
	log.Println("HTTP transport listening on port", h.port)

	return listener
}

func NewHTTP(config HTTPConfig) Transport {
	return &httpTransport{
		port:  config.Port,
		store: config.Store,
	}
}
