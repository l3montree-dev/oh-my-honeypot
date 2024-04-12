package honeypot

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"gitlab.com/neuland-homeland/honeypot/packages/utils"
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
	http.HandleFunc("/{path...}", func(w http.ResponseWriter, r *http.Request) {
		useragent := split(r.UserAgent())
		remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		sub, _ := utils.NetAddrToIpStr(remoteAddr)
		h.setChan <- set.Token{
			SUB: sub,
			ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot/tcp",
			IAT: time.Now().Unix(),
			JTI: uuid.New().String(),
			TOE: time.Now().Unix(),
			Events: map[string]map[string]interface{}{
				HTTPEventID: {
					"port":        h.port,
					"accept-lang": r.Header.Get("Accept-Language"),
					"user-agent":  useragent,
					"path":        r.URL.Path,
				},
			},
		}

		fmt.Fprint(w, "Hello")
	})
	slog.Info("HTTP Honeypot started", "port", h.port)
	go func() {
		for {
			err := http.ListenAndServe(":8080", nil)
			if err != nil {
				slog.Error("Error starting HTTP server", "port", h.port, "err", err)
				continue
			}
		}
	}()
	return nil
}

func split(useragent string) []string {
	splitUserAgent := strings.Split(strings.ReplaceAll(useragent, ") ", ")\n"), "\n")
	if len(splitUserAgent) != 3 {
		splitUserAgent = append(splitUserAgent, "", "")
	}
	return splitUserAgent
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
