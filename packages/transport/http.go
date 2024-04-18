package transport

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"gitlab.com/neuland-homeland/honeypot/packages/honeypot"
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

func getPort(token set.Token) int {
	if token.Events[honeypot.LoginEventID] != nil {
		return 22
	} else if token.Events[honeypot.PortEventID] != nil {
		port, err := strconv.Atoi(token.Events[honeypot.PortEventID]["port"].(string))
		if err != nil {
			return 0
		}
		return port
	}
	return 0
}

func marshalMsgs(r *http.Request, msgs []set.Token) ([]byte, error) {
	if r.URL.Query().Get("format") == "csv" || r.Header.Get("Accept") == "text/csv" {
		var csv string
		for _, msg := range msgs {
			csv += fmt.Sprintf("%d,%s,%s,%d\n", msg.TOE, msg.SUB, msg.COUNTRY, getPort(msg))
		}
		return []byte(csv), nil
	}
	arr, err := json.Marshal(msgs)
	if err != nil {
		return nil, err
	}
	return arr, nil
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

	http.Handle("/hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.store.Get()
			arr, err := marshalMsgs(r, msgs)
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
	slog.Info("HTTP transport listening", "port", h.port)

	return listener
}

func NewHTTP(config HTTPConfig) Transport {
	return &httpTransport{
		port:  config.Port,
		store: config.Store,
	}
}
