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
	GetAttacksIn24Hours() []set.Token
	GetStatsIP() []set.Token
	GetStatsCountry() []set.Token
	GetStatsPort() []set.Token
	GetStatsUsername() []set.Token
	GetStatsPassword() []set.Token
	GetStatsURL() []set.Token
}

type HTTPConfig struct {
	Port   int
	Getter getter
}

type httpTransport struct {
	port   int
	getter getter
}
type myServeMux struct {
	mux http.ServeMux
}

func marshalMsgs(r *http.Request, msgs []set.Token) ([]byte, error) {
	if r.URL.Query().Get("format") == "csv" || r.Header.Get("Accept") == "text/csv" {
		var csv string
		for _, msg := range msgs {
			csv += fmt.Sprintf("%d,%s,%s,%d\n", msg.IAT, msg.SUB, msg.JTI, getPort(msg))
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
	mux.Handle("/attacks-in-24hours", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.getter.GetAttacksIn24Hours()
			arr, err := marshalMsgs(r, msgs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			w.Write(arr) // nolint
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	mux.Handle("/stats/ip-address", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.getter.GetStatsIP()
			arr, err := marshalMsgs(r, msgs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			w.Write(arr) // nolint
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	mux.Handle("/stats/country", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.getter.GetStatsCountry()
			arr, err := marshalMsgs(r, msgs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			w.Write(arr) // nolint
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	mux.Handle("/stats/port", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.getter.GetStatsPort()
			arr, err := marshalMsgs(r, msgs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			w.Write(arr) // nolint
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	mux.Handle("/stats/username", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.getter.GetStatsUsername()
			arr, err := marshalMsgs(r, msgs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			w.Write(arr) // nolint
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	mux.Handle("/stats/password", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.getter.GetStatsPassword()
			arr, err := marshalMsgs(r, msgs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			w.Write(arr) // nolint
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	mux.Handle("/stats/url", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// check if the request would like a json or a csv response - default is json
			// but csv is much smaller
			msgs := h.getter.GetStatsURL()
			arr, err := marshalMsgs(r, msgs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
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

func NewServeMux() *myServeMux {
	return &myServeMux{
		mux: http.ServeMux{},
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
