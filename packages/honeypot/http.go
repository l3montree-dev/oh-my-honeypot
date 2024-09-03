package honeypot

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"sort"

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

const headTemplate = `
	<!DOCTYPE html>
	<html lang="en">

	<head>
    <meta charset="ISO-8859-1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File share system</title>
    <style>
        body {
            background: linear-gradient(to right, #b0b0b0, #c0c0c0);
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }

        .login-wrapper {
            display: flex;
            background-color: #e0e0e0;
            border: 2px solid #808080;
            border-radius: 0px;
            width: 90%;
            max-width: 550px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.3);
        }


        .login-image {
            flex: 1;
            background: url('https://cdn.pixabay.com/photo/2014/04/03/00/39/server-309012_1280.png') no-repeat center center;
            background-size: 40%;
            border-top-left-radius: 0px;
            border-bottom-left-radius: 0px;
        }

        .login-container {
            flex: 1;
            padding: 20px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }

        .login-container h2 {
            color: #404040;
            font-size: 22px;
            margin-bottom: 7px;
            margin-top: 10px;
        }

        .login-container h3 {
            color: #606060;
            font-size: 14px;
            margin-bottom: 10px;
        }

        .textbox {
            margin: 8px ;
            width: 100%;
        }

        .textbox input {
            width: 100%;
            padding: 3px;
            border: 1px solid #808080;
            background-color: #d0d0d0;
            color: #404040;
            border-radius: 0px;
        }

        .btn {
			position: relative;
			left: 60px;
            width: 40%;
            padding: 3px;
            background-color: #404040;
            color: #d0d0d0;
            border: none;
            border-radius: 15px;
            cursor: pointer;
            font-size: 13px;
            margin-top: 7px;
        }

        .btn:hover {
            background-color: linear-gradient(to right, #b0b0b0, #c0c0c0);
        }
		.error-wrapper {
			padding: 7px;
			border: 1px solid #ccc;
			background-color: #f9f9f9;
			border-radius: 5px;
			margin-top: 7px;
			width: 90%;
            max-width: 350px;
			
		}

		.error-message {
			color: red;
			margin-top: 10px;
			font-size: 14px;
		}
    </style>
	</head>
`
const loginTemplate = `
    <div class="login-wrapper">
        <div class="login-image"></div>
        <div class="login-container">
            <h2>Internal NAS Server</h2>
            <h3>Member Login</h3>
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

	`
const pagenotfoundTemplate = `
	<div class="error-wrapper">
		<h1>404 Not Found</h1>
		<p>Page not found</p>
		<p><a href="/index.php">Main page</a></p>
	</div>
`
const notallowedTemplate = `
	<div class="error-wrapper">
		<h1>405 Method Not Allowed</h1>
		<p>Method not allowed</p>
		<p><a href="/index.php">Main page</a></p>
	</div>
`

func (h *httpHoneypot) Start() error {
	mux := http.NewServeMux()
	// Common logging and data extraction functions
	extractRequestData := func(r *http.Request) (string, []string, []byte, string, string, string, string, string, error) {
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
		defer r.Body.Close()
		if err != nil {
			slog.Error("Error reading request body", "err", err)
		}
		// Reset the body so it can be read again by ParseForm()
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		referrer := r.Header.Get("Referer")
		username := r.FormValue("username")
		password := r.FormValue("password")
		bot := r.FormValue("lastname")

		mimeType := http.DetectContentType(body)
		return sub, useragent, body, mimeType, referrer, username, password, bot, nil
	}
	handleRequest := func(w http.ResponseWriter, r *http.Request, extraData map[string]interface{}) {
		sub, useragent, body, mimeType, referrer, username, password, bot, err := extractRequestData(r)
		if err != nil {
			slog.Error("Error processing request", "err", err)
		}
		event := map[string]interface{}{
			"port":         h.port,
			"method":       r.Method,
			"accept-lang":  r.Header.Get("Accept-Language"),
			"user-agent":   useragent,
			"content-type": mimeType,
			"body":         string(body),
			"bodysize":     len(body),
			"path":         r.URL.Path,
			"referrer":     referrer,
			"username":     username,
			"password":     password,
			"bot":          bot,
		}
		// Merge extraData into the event map
		for k, v := range extraData {
			event[k] = v
		}

		h.setChan <- types.Set{
			SUB: sub,
			ISS: "github.com/l3montree-dev/oh-my-honeypot/packages/honeypot/http",
			IAT: time.Now().Unix(),
			JTI: uuid.New().String(),
			Events: map[string]map[string]interface{}{
				HTTPEventID: event,
			},
		}
		for key, value := range viper.GetStringMap("http.headers") {
			w.Header().Set(key, value.(string))
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, nil)
		q := r.URL.Query()
		if q.Get("page") == "login" && q.Get("param") == "wrongauthentication" {
			if r.Method != "POST" {
				htmlContent := fmt.Sprintf(`<!DOCTYPE html>
				<html lang="en">
				%s
				<body>
				%s
				</body>
				</html>`, headTemplate, notallowedTemplate)
				w.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprint(w, htmlContent)
				return
			}
			htmlContent := fmt.Sprintf(`<!DOCTYPE html>
			<html lang="en">
			%s
			<body>
			%s
			<p id="error-message" class="error-message">Wrong username or password</p>
			</body>
			</html>`, headTemplate, loginTemplate)
			fmt.Fprint(w, htmlContent)
		} else if r.URL.Path == "/" || r.URL.Path == "/index.php" {
			htmlContent := fmt.Sprintf(`<!DOCTYPE html>
			<html lang="en">
			%s
			<body>
			%s
			</body>
			</html>`, headTemplate, loginTemplate)

			fmt.Fprint(w, htmlContent)
		} else {
			htmlContent := fmt.Sprintf(`<!DOCTYPE html>
			<html lang="en">
			%s
			<body>
			%s
			</body>
			</html>`, headTemplate, pagenotfoundTemplate)

			fmt.Fprint(w, htmlContent)
		}
	})

	mux.HandleFunc("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, nil)
		fmt.Fprint(w, "")
	})

	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		randomPW, err := password.Generate(16, 4, 4, false, false)
		handleRequest(w, r, map[string]interface{}{
			"randomPW":    randomPW,
			"attack-type": "credential-theft",
		})

		envMap := viper.GetStringMap("http.env")
		keys := make([]string, 0, len(envMap))
		for key := range envMap {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		envString := "# Outdated as of 2016-02-03 \n"
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
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, envString)
	})
	slog.Info("HTTP Honeypot started", "port", h.port)
	// HTTP Server
	go func() {
		for {
			err := http.ListenAndServe(":80", mux)
			if err != nil {
				slog.Error("Error starting HTTP redirect server", "err", err)
			}
		}
	}()
	// HTTPS server
	go func() {
		for {
			svc := http.Server{
				Addr:     ":443",
				Handler:  mux,
				ErrorLog: log.New(io.Discard, "", 0),
			}
			err := svc.ListenAndServeTLS(h.cert, h.key)
			if err != nil {
				slog.Error("Error starting HTTPS server", "port", 443, "err", err)
				break
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
