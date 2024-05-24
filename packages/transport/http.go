package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/l3montree-dev/oh-my-honeypot/packages/honeypot"
	"github.com/l3montree-dev/oh-my-honeypot/packages/set"
)

type getter interface {
	GetAttacksIn24Hours() []set.Token
	GetAttacksIn7Days() []set.Token
	GetStatsIP() []set.Token
	GetStatsCountry() []set.Token
	GetStatsPort() []set.Token
	GetStatsUsername() []set.Token
	GetStatsPassword() []set.Token
	GetStatsURL() []set.Token
}

type HTTPConfig struct {
	Port         int
	Getter       getter
	RealtimeChan chan set.Token
}

type httpTransport struct {
	port         int
	getter       getter
	RealtimeChan chan set.Token
	sockets      map[string]chan set.Token
}

func NewHTTP(config HTTPConfig) *httpTransport {
	httpTransport := &httpTransport{
		port:         config.Port,
		getter:       config.Getter,
		RealtimeChan: config.RealtimeChan,
		sockets:      make(map[string]chan set.Token),
	}

	go func() {
		for msg := range httpTransport.RealtimeChan {
			for _, ch := range httpTransport.sockets {
				ch <- msg
			}
		}
	}()
	return httpTransport
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
	mux.Handle("GET /realtime", h.HandleSSE())
	mux.Handle("GET /attacks-in-24hours", http.HandlerFunc(h.getAttacksIn24Hours))
	mux.Handle("GET /attacks-in-7days", http.HandlerFunc(h.getAttacksIn7Days))
	mux.Handle("GET /stats/country", http.HandlerFunc(h.getStatsCountry))
	mux.Handle("GET /stats/ip", http.HandlerFunc(h.getStatsIP))
	mux.Handle("GET /stats/port", http.HandlerFunc(h.getStatsPort))
	mux.Handle("GET /stats/username", http.HandlerFunc(h.getStatsUsername))
	mux.Handle("GET /stats/password", http.HandlerFunc(h.getstatsPassword))
	mux.Handle("GET /stats/url", http.HandlerFunc(h.getStatsURL))

	go http.ListenAndServe(":"+fmt.Sprintf("%d", h.port), mux) // nolint
	slog.Info("HTTP transport listening", "port", h.port)
}
func setDefaultHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// GET funtions of API Endpoint
func (h *httpTransport) getAttacksIn24Hours(w http.ResponseWriter, r *http.Request) {
	msgs := h.getter.GetAttacksIn24Hours()
	arr, err := marshalMsgs(r, msgs)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	setDefaultHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(arr) // Check the error return value of w.Write
	if err != nil {
		// Handle the error appropriately
		return
	}
}

func (h *httpTransport) getAttacksIn7Days(w http.ResponseWriter, r *http.Request) {
	msgs := h.getter.GetAttacksIn7Days()
	arr, err := marshalMsgs(r, msgs)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	setDefaultHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(arr) // Check the error return value of w.Write
	if err != nil {
		// Handle the error appropriately
		return
	}
}

func (h *httpTransport) getStatsCountry(w http.ResponseWriter, r *http.Request) {
	msgs := h.getter.GetStatsCountry()
	arr, err := marshalMsgs(r, msgs)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	setDefaultHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(arr) // Check the error return value of w.Write
	if err != nil {
		// Handle the error appropriately
		return
	}
}

func (h *httpTransport) getStatsIP(w http.ResponseWriter, r *http.Request) {
	msgs := h.getter.GetStatsIP()
	arr, err := marshalMsgs(r, msgs)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	setDefaultHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(arr) // Check the error return value of w.Write
	if err != nil {
		// Handle the error appropriately
		return
	}
}

func (h *httpTransport) getStatsPort(w http.ResponseWriter, r *http.Request) {
	msgs := h.getter.GetStatsPort()
	arr, err := marshalMsgs(r, msgs)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	setDefaultHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(arr) // Check the error return value of w.Write
	if err != nil {
		// Handle the error appropriately
		return
	}
}

func (h *httpTransport) getStatsUsername(w http.ResponseWriter, r *http.Request) {
	msgs := h.getter.GetStatsUsername()
	arr, err := marshalMsgs(r, msgs)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	setDefaultHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(arr) // Check the error return value of w.Write
	if err != nil {
		// Handle the error appropriately
		return
	}

}

func (h *httpTransport) getstatsPassword(w http.ResponseWriter, r *http.Request) {
	msgs := h.getter.GetStatsPassword()
	arr, err := marshalMsgs(r, msgs)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	setDefaultHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(arr) // Check the error return value of w.Write
	if err != nil {
		// Handle the error appropriately
		return
	}
}
func (h *httpTransport) getStatsURL(w http.ResponseWriter, r *http.Request) {
	msgs := h.getter.GetStatsURL()
	arr, err := marshalMsgs(r, msgs)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	setDefaultHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(arr) // Check the error return value of w.Write
	if err != nil {
		// Handle the error appropriately
		return
	}
}

func (h *httpTransport) HandleSSE() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		ch := make(chan set.Token)
		randomString := uuid.New().String()
		h.sockets[randomString] = ch
		slog.Info("New connection", "connectionId", randomString)
		defer func() {
			slog.Info("Closing connection", "connectionId", randomString)
			delete(h.sockets, randomString)
		}()

		for {
			message, ok := <-ch
			if !ok {
				log.Printf("Channel closed")
				return
			}

			arr, _ := json.Marshal(message)

			_, err := w.Write([]byte("data: " + string(arr) + "\n\n"))
			if err != nil {
				log.Printf("Error writing to response: %v", err)
				return
			}

			flusher.Flush()
		}
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
