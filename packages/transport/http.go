package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
)

type getter interface {
	GetLatestAttacks() types.SetResponse
	GetIPStats() types.IPStatsResponse
	GetCountryStats() types.CountryStatsResponse
	GetPortStats() types.PortStatsResponse
	GetUsernameStats() types.UsernameStatsResponse
	GetPasswordStats() types.PasswordStatsResponse
	GetPathStats() types.PathStatsResponse
	GetCountIn24Hours() types.CountIn24HoursStatsResponse
	GetCountIn7Days() types.CountIn7DaysStatsResponse
	GetCountIn6Months() types.CountIn6MonthsStatsResponse
	GetCountIn24HoursByCountry() types.CountIn24HoursByCountryResponse
}

type HTTPConfig struct {
	Port         int
	Getter       getter
	RealtimeChan chan types.Set
}

type httpTransport struct {
	port         int
	getter       getter
	RealtimeChan chan types.Set
	sockets      map[string]chan types.Set
}

func NewHTTP(config HTTPConfig) *httpTransport {
	httpTransport := &httpTransport{
		port:         config.Port,
		getter:       config.Getter,
		RealtimeChan: config.RealtimeChan,
		sockets:      make(map[string]chan types.Set),
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

// Set default HTTP headers
func setDefaultHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func cacheControlMiddleware(maxAge int, staleWhileRevalidateMaxAge int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set the Cache-Control header
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, stale-while-revalidate=%d", maxAge, staleWhileRevalidateMaxAge))

			// Continue with the next handler
			next.ServeHTTP(w, r)
		})
	}
}

func (h *httpTransport) Listen() {
	// create a new http server
	mux := http.NewServeMux()
	// the response is fresh for 1 hour, it can be served stale for 1 day
	cachingMiddleware := cacheControlMiddleware(60*60, 60*60*24)

	mux.Handle("GET /realtime", h.handleSSE())
	mux.Handle("GET /latest-attacks", cachingMiddleware(h.handleLatestAttacks()))
	mux.Handle("GET /stats/count-in-24hours-by-country", cachingMiddleware(h.handleCountIn24HoursByCountry()))
	mux.Handle("GET /stats/count-in-24hours", cachingMiddleware(h.handleCountIn24Hours()))
	mux.Handle("GET /stats/count-in-7days", cachingMiddleware(h.handleCountIn7Days()))
	mux.Handle("GET /stats/count-in-6months", cachingMiddleware(h.handleCountIn6Monts()))
	mux.Handle("GET /stats/country", cachingMiddleware(h.handleCountryStats()))
	mux.Handle("GET /stats/ip", cachingMiddleware(h.handleIPStats()))
	mux.Handle("GET /stats/port", cachingMiddleware(h.handlePortStats()))
	mux.Handle("GET /stats/username", cachingMiddleware(h.handleUsernameStats()))
	mux.Handle("GET /stats/password", cachingMiddleware(h.handlePasswordStats()))
	mux.Handle("GET /stats/path", cachingMiddleware(h.handlePathStats()))
	mux.Handle("GET /health", cachingMiddleware(h.handleHealth()))

	go http.ListenAndServe(":"+fmt.Sprintf("%d", h.port), mux) // nolint
	slog.Info("HTTP transport listening", "port", h.port)
}

func (h *httpTransport) handleCountIn24HoursByCountry() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetCountIn24HoursByCountry()
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
		ch := make(chan types.Set)
		randomString := uuid.New().String()
		h.sockets[randomString] = ch
		// slog.Info("New connection", "connectionId", randomString)
		defer func() {
			// slog.Info("Closing connection", "connectionId", randomString)
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

// handleLatestAttacks handles the request for attacks in the last 24 hours
func (h *httpTransport) handleLatestAttacks() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetLatestAttacks()
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

// handleCountIn24Hours handles the request for number of attacks per hour for last 24hours
func (h *httpTransport) handleCountIn24Hours() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetCountIn24Hours()
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

// handleCountIn7Days handles the request for number of attacks per day for last 7 days
func (h *httpTransport) handleCountIn7Days() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetCountIn7Days()
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

// handleCountIn6Monts handles the request for number of attacks per month for last 6 months
func (h *httpTransport) handleCountIn6Monts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetCountIn6Months()
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

// handleStatsCountry handles the request for number of attacks per country
func (h *httpTransport) handleCountryStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetCountryStats()
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
func (h *httpTransport) handleIPStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetIPStats()
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

// handleStatsUsername handles the request for number of attacks per username
func (h *httpTransport) handleUsernameStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetUsernameStats()
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

// handleStatsPassword handles the request for number of attacks per password
func (h *httpTransport) handlePasswordStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetPasswordStats()
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

// handleStatsPort handles the request for number of attacks per port
func (h *httpTransport) handlePortStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetPortStats()
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

// handleStatsURL handles the request for number of attacks per URL
func (h *httpTransport) handlePathStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		msgs := h.getter.GetPathStats()
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

func (h *httpTransport) handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
