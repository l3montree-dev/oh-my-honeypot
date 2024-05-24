package honeypot

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/oh-my-honeypot/packages/set"
	"github.com/l3montree-dev/oh-my-honeypot/packages/utils"
	"github.com/spf13/viper"
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
	mux := http.NewServeMux()
	mux.HandleFunc("/{path...}", func(w http.ResponseWriter, r *http.Request) {
		useragent := split(r.UserAgent())
		remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		sub, _ := utils.NetAddrToIpStr(remoteAddr)
		body, _ := io.ReadAll(r.Body)
		mimeType := http.DetectContentType(body)
		defer r.Body.Close()
		h.setChan <- set.Token{
			SUB: sub,
			ISS: "github.com/l3montree-dev/oh-my-honeypot/packages/honeypot/http",
			IAT: time.Now().Unix(),
			JTI: uuid.New().String(),
			Events: map[string]map[string]interface{}{
				HTTPEventID: {
					"port":         h.port,
					"method":       r.Method,
					"accept-lang":  r.Header.Get("Accept-Language"),
					"user-agent":   useragent,
					"content-type": mimeType,
					"body":         string(body),
					"bodysize":     len(body),
					"path":         r.URL.Path,
				},
			},
		}
		vi := viper.New()
		vi.AddConfigPath(".")
		vi.SetConfigFile("vuln-config.yaml")
		err := vi.ReadInConfig()
		if err != nil {
			fmt.Println("Error on Reading Viper Config")
			panic(err)
		}
		// Set the headers to make the honeypot look like an vulnerable server
		//iterate over the headers and set them
		for key, value := range vi.GetStringMap("http.headers") {
			w.Header().Set(key, value.(string))
		}
		fmt.Fprint(w, "Hello")

	})
	slog.Info("HTTP Honeypot started", "port", h.port)
	go func() {
		for {
			err := http.ListenAndServe(":80", mux)
			if err != nil {
				slog.Error("Error starting HTTP server", "port", h.port, "err", err)
				continue
			}
		}
	}()
	return nil
}

// split splits the useragent string into 3 parts.
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
