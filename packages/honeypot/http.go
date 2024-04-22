package honeypot

import (
	"fmt"
	"log/slog"
	"net/http"

	"gitlab.com/neuland-homeland/honeypot/packages/set"
)

type httpHoneypot struct {
	port int
	// setChan is the channel the honeypot is posting SET events to.
	setChan chan set.Token
}

type HTTPConfig struct {
	Port int
}

func (h *httpHoneypot) Start() error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		/*
			//sub, _ := utils.NetAddrToIpStr
			token := set.Token{
				//SUB: sub,
				ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot/tcp",
				IAT: time.Now().Unix(),
				JTI: uuid.New().String(),
				TOE: time.Now().Unix(),
				Events: map[string]map[string]interface{}{
					PortEventID: {
						"port": fmt.Sprintf("%d", h.port),
					},
				},
			}
			h.setChan <- token

		*/
		fmt.Fprint(w, "Hello")
	})
	go func() {
		for {
			err := http.ListenAndServe("127.0.0.1:8080", nil)
			if err != nil {
				slog.Error("Error starting HTTP server", "port", h.port, "err", err)
				return
			}
			slog.Info("HTTP Honeypot started", "port", h.port)
		}
	}()
	return nil
}

// GetSETChannel implements Honeypot.
func (h *httpHoneypot) GetSETChannel() <-chan set.Token {
	return h.setChan
}

func NewHTTP(config HTTPConfig) Honeypot {
	return &httpHoneypot{
		port:    config.Port,
		setChan: make(chan set.Token),
	}
}
