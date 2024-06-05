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
	GetStatsIP() []set.Token
	GetStatsCountry() map[string]any
	GetStatsPort() []set.Token
	GetStatsUsername() []set.Token
	GetStatsPassword() []set.Token
	GetStatsURL() []set.Token
	GetCountIn24Hours() []set.Token
	GetCountIn7Days() []set.Token
	GetCountIn6Months() []set.Token
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

// Set default HTTP headers
func setDefaultHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func (h *httpTransport) Listen() {
	// create a new http server
	mux := http.NewServeMux()
	mux.Handle("GET /realtime", h.handleSSE())
	mux.Handle("GET /attacks-in-24hours", h.handleAttacksIn24Hours())
	mux.Handle("GET /stats/count-in-24hours", h.handleCountIn24Hours())
	mux.Handle("GET /stats/count-in-7days", h.handleCountIn7Days())
	mux.Handle("GET /stats/count-in-6months", h.handleCountIn6Monts())
	mux.Handle("GET /stats/country", h.handleStatsCountry())
	mux.Handle("GET /stats/ip", h.handleStatsIP())
	mux.Handle("GET /stats/port", h.handleStatsPort())
	mux.Handle("GET /stats/username", h.handleStatsUsername())
	mux.Handle("GET /stats/password", h.handleStatsPassword())
	mux.Handle("GET /stats/url", h.handleStatsURL())

	go http.ListenAndServe(":"+fmt.Sprintf("%d", h.port), mux) // nolint
	slog.Info("HTTP transport listening", "port", h.port)
}

// HandleSSE handles the server-sent events for real time attack data
func (h *httpTransport) handleSSE() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//set headers for server-sent events
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

// handleAttacksIn24Hours handles the request for attacks in the last 24 hours
func (h *httpTransport) handleAttacksIn24Hours() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// handleCountIn24Hours handles the request for number of attacks per hour for last 24hours
func (h *httpTransport) handleCountIn24Hours() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetCountIn24Hours()
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
}

// handleCountIn7Days handles the request for number of attacks per day for last 7 days
func (h *httpTransport) handleCountIn7Days() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetCountIn7Days()
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
}

// handleCountIn6Monts handles the request for number of attacks per month for last 6 months
func (h *httpTransport) handleCountIn6Monts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetCountIn6Months()
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
}

// handleStatsCountry handles the request for number of attacks per country
func (h *httpTransport) handleStatsCountry() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetStatsCountry()
		arr, err := json.Marshal(msgs)
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
}

// handleStatsIP handles the request for number of attacks per IP
func (h *httpTransport) handleStatsIP() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// handleStatsUsername handles the request for number of attacks per username
func (h *httpTransport) handleStatsUsername() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// handleStatsPassword handles the request for number of attacks per password
func (h *httpTransport) handleStatsPassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// handleStatsPort handles the request for number of attacks per port
func (h *httpTransport) handleStatsPort() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
}

// handleStatsURL handles the request for number of attacks per URL
func (h *httpTransport) handleStatsURL() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
