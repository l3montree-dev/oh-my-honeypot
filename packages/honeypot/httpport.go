package honeypot

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
)

type httpPortHoneypot struct {
	ports   []int
	setChan chan set.Token
}

func (h *httpPortHoneypot) Start() error {
	// create a tcp listener for each port
	// create a goroutine for each listener
	for _, port := range h.ports {
		go func(port int) {
			log.Println("Starting HTTP honeypot on port", port)
			http.ListenAndServe("0.0.0.0:"+fmt.Sprintf("%d", port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.setChan <- set.Token{
					SUB: r.RemoteAddr,
					ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot/httpports",
					IAT: time.Now().Unix(),
					JTI: uuid.New().String(),
					TOE: time.Now().Unix(),
					Events: map[string]map[string]interface{}{
						"https://gitlab.com/neuland-homeland/honeypot/json-schema/http-port": {
							"port":       fmt.Sprintf("%d", port),
							"user-agent": r.UserAgent(),
						},
					},
				}
				w.WriteHeader(http.StatusNotFound)
			}))
		}(port)
	}
	return nil
}

func (h *httpPortHoneypot) GetSETChannel() <-chan set.Token {
	return h.setChan
}

func NewHttpPort(ports []int) Honeypot {
	return &httpPortHoneypot{
		setChan: make(chan set.Token),
		ports:   ports,
	}
}
