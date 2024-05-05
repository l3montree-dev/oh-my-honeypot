package transport

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/l3montree-dev/oh-my-honeypot/packages/honeypot"
	"github.com/l3montree-dev/oh-my-honeypot/packages/set"
)

type getter interface {
	GetAttacks() []set.Token
}

type HTTPConfig struct {
	Port   int
	Getter getter
}

type httpTransport struct {
	port   int
	getter getter
}

func marshalMsgs(r *http.Request, msgs []set.Token) ([]byte, error) {
	if r.URL.Query().Get("format") == "csv" || r.Header.Get("Accept") == "text/csv" {
		var csv string
		for _, msg := range msgs {
			csv += fmt.Sprintf("%d,%s,%s,%d\n", msg.IAT, msg.SUB, msg.COUNTRY, getPort(msg))
		}
		return []byte(csv), nil
	}
	arr, err := json.Marshal(msgs)
	if err != nil {
		return nil, err
	}
	return arr, nil
}

func (h *httpTransport) Listen() {
	// create a new http server
	mux := http.NewServeMux()
	mux.Handle("/attacks", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.getter.GetAttacks()
			arr, err := marshalMsgs(r, msgs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(200)
			w.Write(arr) // nolint
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	go http.ListenAndServe(":"+fmt.Sprintf("%d", h.port), mux) // nolint
	slog.Info("HTTP transport listening", "port", h.port)

}

func NewHTTP(config HTTPConfig) *httpTransport {
	return &httpTransport{
		port:   config.Port,
		getter: config.Getter,
	}
}

func getPort(input set.Token) int {
	var portEvent map[string]interface{}

	if ev, ok := input.Events[honeypot.PortEventID]; ok {
		portEvent = ev
	} else if ev, ok := input.Events[honeypot.LoginEventID]; ok {
		portEvent = ev
	} else if ev, ok := input.Events[honeypot.LoginEventID]; ok {
		portEvent = ev
	}

	// the port is either float64 or int
	// so we need to cast it to int
	switch portEvent["port"].(type) {
	case float64:
		return int(portEvent["port"].(float64))
	case int:
		return portEvent["port"].(int)
	}
	return 0
}
