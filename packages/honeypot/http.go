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
	"github.com/sethvargo/go-password/password"
	"github.com/spf13/viper"
)

type httpsHoneypot struct {
	port int
	cert string
	key  string
}

type httpHoneypot struct {
	port int
	// setChan is the channel the honeypot is posting SET events to.
	setChan chan types.Set
	httpsHoneypot
}

type HTTPSConfig struct {
	Port     int
	CertFile string
	KeyFile  string
}

type HTTPConfig struct {
	Port int
	HTTPSConfig
}

const htmlTemplate = `
	<!DOCTYPE html>
	<html lang="en">

	<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Login - Small Business NAS</title>
	<style>
		body {
		font-family: Arial, sans-serif;
		background-color: #dcdcdc;
		color: #000;
		text-align: center;
		margin: 0;
		padding: 0;
		}

		.login-container {
		display: inline-block;
		margin-top: 100px;
		padding: 20px;
		border: 1px solid #aaa;
		background: linear-gradient(145deg, #e0e0e0, #a0a0a0);
		box-shadow: 5px 5px 15px rgba(0, 0, 0, 0.3);
		width: 300px;
		border-radius: 8px;
		}

		h1 {
		font-size: 24px;
		color: #333;
		margin-bottom: 20px;
		}

		.textbox {
		margin-bottom: 10px;
		}

		input[type="text"],
		input[type="password"] {
		width: calc(100% - 20px);
		padding: 8px;
		margin-bottom: 10px;
		border: 1px solid #888;
		border-radius: 4px;
		font-size: 14px;
		background-color: #f0f0f0;
		}

		button[type="submit"] {
		background-color: #444;
		color: #fff;
		border: none;
		padding: 10px;
		width: 100%;
		cursor: pointer;
		font-size: 14px;
		border-radius: 4px;
		margin-top: 10px;
		}

		button[type="submit"]:hover {
		background-color: #333;
		}

		.footer {
		margin-top: 20px;
		font-size: 12px;
		color: #555;
		}
	</style>
	</head>

	<body>
	<div class="login-container">
		<h1>NAS Login</h1>
		<form action="/index.php?page=login&param=wrongauthentication" method="POST" id="form">
		<div class="textbox">
			<input type="text" placeholder="Username" name="username" id="username" required>
		</div>
		<div class="textbox">
			<input type="password" placeholder="Password" name="password" id="password" required>
		</div>
		<div class="textbox" id="lastname-box" style="display: none;">
			<input type="text" placeholder="Lastname" name="lastname" id="lastname">
		</div>
		<button type="submit" class="btn">Login</button>
		</form>
	</div>
	</body>

	</html>
	`

func (h *httpHoneypot) Start() error {
	mux := http.NewServeMux()
	// Common logging and data extraction functions
	extractRequestData := func(r *http.Request) (string, []string, []byte, string, string, error) {
		useragent := split(r.UserAgent())
		remoteAddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		if err != nil {
			slog.Error("Error resolving remote address", "err", err)

		}
		sub, err := utils.NetAddrToIpStr(remoteAddr)
		if err != nil {
			slog.Error("Error converting remote address to IP string", "err", err)

		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Error reading request body", "err", err)
		}
		mimeType := http.DetectContentType(body)
		referrer := r.Header.Get("Referer")
		return sub, useragent, body, mimeType, referrer, nil

	}
	handleRequest := func(w http.ResponseWriter, r *http.Request, extraData map[string]interface{}) {
		sub, useragent, body, mimeType, referrer, err := extractRequestData(r)
		if err != nil {
			slog.Error("Error processing request", "err", err)
		}
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
					"referrer":     referrer,
				},
			},
		}
		//vulnable config
		for key, value := range viper.GetStringMap("http.headers") {
			w.Header().Set(key, value.(string))
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, nil)
		if r.URL.Path == "/" || r.URL.Path == "/index.php" {
			fmt.Fprint(w, htmlTemplate)
		} else {
			fmt.Fprint(w, "Hello")
		}
	})
	mux.HandleFunc("/index.php?page=login&param=wrongauthentication", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		body := username + "\n" + password + "\n"

		handleRequest(w, r, map[string]interface{}{
			"username":    username,
			"password":    password,
			"body":        body,
			"attack-type": "injection",
		})

		fmt.Fprint(w, "Login failed: Invalid credentials")
	})

	mux.HandleFunc("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, nil)

		var response map[string]interface{}
		if r.Method == http.MethodGet {
			response = map[string]interface{}{
				"status":  "error",
				"message": "No input provided. Please send PHP code to execute.",
			}
		} else if r.Method == http.MethodPost || r.Method == http.MethodPut {
			response = map[string]interface{}{
				"status":  "error",
				"message": "Error executing code: syntax error, unexpected end of file",
			}
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, nil)

		envMap := viper.GetStringMap("http.env")
		keys := make([]string, 0, len(envMap))
		for key := range envMap {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		envString := "# Outdated as of 2016-02-03 \n"
		randomPW, err := password.Generate(16, 4, 4, false, false)
		if err != nil {
			slog.Error("Error generating random password", "err", err)
			return
		}
		for _, key := range keys {
			switch key {
			case "ssh_password", "db_password":
				envString += fmt.Sprintf("%s=%s\n", strings.ToUpper(key), randomPW)
			default:
				value := envMap[key]
				envString += fmt.Sprintf("%s=%s\n", strings.ToUpper(key), value)
			}
		}
		fmt.Fprint(w, envString)
	})

	// HTTP to HTTPS redirect
	go func() {
		httpMux := http.NewServeMux()
		httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		if err := http.ListenAndServe(":80", httpMux); err != nil {
			slog.Error("Error starting HTTP redirect server", "err", err)
		}
	}()
	slog.Info("HTTP Honeypot started", "port", h.port)
	// HTTPS server
	go func() {
		for {
			err := http.ListenAndServeTLS(":443", h.cert, h.key, mux)
			if err != nil {
				slog.Error("Error starting HTTPS server", "port", h.port, "err", err)
				time.Sleep(time.Second) // Avoid tight loop on error
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
		httpsHoneypot: httpsHoneypot{
			port: config.Port,
			key:  config.KeyFile,
			cert: config.CertFile,
		},
	}
}
