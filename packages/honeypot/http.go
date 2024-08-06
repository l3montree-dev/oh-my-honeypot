package honeypot

import (
	"encoding/json"
	"fmt"
	"sort"

	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
	"github.com/l3montree-dev/oh-my-honeypot/packages/utils"
	"github.com/spf13/viper"
)

type httpHoneypot struct {
	port int
	// setChan is the channel the honeypot is posting SET events to.
	setChan chan types.Set
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
		h.setChan <- types.Set{
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
		// Set the headers to make the honeypot look like an vulnerable server
		//iterate over the headers and set them
		for key, value := range viper.GetStringMap("http.headers") {
			w.Header().Set(key, value.(string))
		}
		fmt.Fprint(w, "Hello, World!")
	})
	// Vulnerable PHP endpoint: CVE-2017-9841 (PHPUnit RCE)
	mux.HandleFunc("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", func(w http.ResponseWriter, r *http.Request) {
		useragent := split(r.UserAgent())
		remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		sub, _ := utils.NetAddrToIpStr(remoteAddr)
		body, _ := io.ReadAll(r.Body)
		mimeType := http.DetectContentType(body)
		defer r.Body.Close()
		h.setChan <- types.Set{
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
		// Set the headers to make the honeypot look like an vulnerable server
		for key, value := range viper.GetStringMap("http.headers") {
			w.Header().Set(key, value.(string))
		}
		if r.Method == http.MethodGet {
			response := map[string]interface{}{
				"status":  "error",
				"message": "No input provided. Please send PHP code to execute.",
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
				return
			}
		} else if r.Method == http.MethodPost || r.Method == http.MethodPut {
			response := map[string]interface{}{
				"status":  "error",
				"message": "Error executing code: syntax error, unexpected end of file",
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
				return
			}
		}
	})

	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		useragent := split(r.UserAgent())
		remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		sub, _ := utils.NetAddrToIpStr(remoteAddr)
		body, _ := io.ReadAll(r.Body)
		mimeType := http.DetectContentType(body)
		defer r.Body.Close()
		h.setChan <- types.Set{
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
		// Set the headers to make the honeypot look like an vulnerable server
		//iterate over the headers and set them
		for key, value := range viper.GetStringMap("http.headers") {
			w.Header().Set(key, value.(string))
		}
		// return the .env file
		envMap := viper.GetStringMap("http.env")
		keys := make([]string, 0, len(envMap))
		for key := range envMap {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		envString := "# Outdated as of 2016-02-03 \n"
		for _, key := range keys {
			value := envMap[key]
			envString += fmt.Sprintf("%s=%s\n", strings.ToUpper(key), value)
		}
		fmt.Fprint(w, envString)
	})

	indexFileserver := http.FileServer(http.Dir("./public/home"))
	loginFileserver := http.FileServer(http.Dir("./public/login"))
	mux.Handle("/index.php/", http.StripPrefix("/index.php/", indexFileserver))
	mux.Handle("/login.php/", http.StripPrefix("/login.php/", loginFileserver))

	// Handle the form submission
	mux.HandleFunc("/failed-login.php", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		useragent := split(r.UserAgent())
		remoteAddr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		sub, _ := utils.NetAddrToIpStr(remoteAddr)
		contentType := r.Header.Get("Content-Type")
		username := r.FormValue("username")
		password := r.FormValue("password")
		body := username + "\n" + password + "\n"
		h.setChan <- types.Set{
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
					"content-type": contentType,
					"path":         r.URL.Path,
					"body":         body,
					"bodysize":     len(body),
					"username":     username,
					"password":     password,
					"attack-type":  "injection",
				},
			},
		}

		fmt.Fprint(w, "Login failed: Invalid credentials")
	})

	// Set the headers to make the honeypot look like an vulnerable server
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
func (h *httpHoneypot) GetSETChannel() <-chan types.Set {
	return h.setChan
}

func NewHTTP(config HTTPConfig) Honeypot {
	return &httpHoneypot{
		port:    config.Port,
		setChan: make(chan types.Set),
	}
}
