package honeypot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
	"github.com/l3montree-dev/oh-my-honeypot/packages/utils"
)

type postgresHoneypot struct {
	port int
	// setChan is the channel the honeypot is posting SET events to.
	setChan chan types.Set
}

type PostgresConfig struct {
	Port int
}

func (p *postgresHoneypot) Start() error {
	// create a new tcp listener on the port
	go func() {
		listener, err := net.Listen("tcp", "0.0.0.0:"+fmt.Sprintf("%d", p.port))
		if err != nil {
			slog.Error("Error creating TCP listener", "port", p.port, "err", err)
			return
		}
		// Accept all connections
		slog.Info("Postgres Honeypot started", "port", p.port)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					slog.Error("failed to accept incoming connection", "err", err)
					continue
				}
				go func(conn net.Conn) {
					defer conn.Close()
					loginReceived := false
					passwordReceived := false
					username := ""
					for {
						sub, _ := utils.NetAddrToIpStr(conn.RemoteAddr())
						msg := make([]byte, 1024)
						n, _ := conn.Read(msg)
						msg = msg[:n]
						if n == 0 && !loginReceived {
							p.setChan <- types.Set{
								SUB: sub,
								ISS: "github.com/l3montree-dev/oh-my-honeypot/packages/honeypot/postgres",
								IAT: time.Now().Unix(),
								JTI: uuid.New().String(),
								Events: map[string]map[string]interface{}{
									PortEventID: {
										"port": p.port,
									},
								},
							}
							return
						}
						// n has to be greater than 0 since we are in the loop
						if isSSLRequest(msg) {
							conn.Write([]byte("N")) // nolint
							continue
						} else if isLoginMessage(msg) {
							username = searchUsername(msg)
							conn.Write(pwAuthResponse()) // nolint
							loginReceived = true
							continue
						} else if isPasswordMessage(msg) && !passwordReceived {
							password := string(msg[5 : len(msg)-1])
							p.setChan <- types.Set{
								SUB: sub,
								ISS: "github.com/l3montree-dev/oh-my-honeypot/packages/honeypot/http",
								IAT: time.Now().Unix(),
								JTI: uuid.New().String(),
								Events: map[string]map[string]interface{}{
									LoginEventID: {
										"username": username,
										"password": password,
										"port":     p.port,
										"service":  "Postgres",
									},
								},
							}
							conn.Write(authErrorResponse()) // nolint
						}
					}
				}(conn)
			}
		}()

	}()
	return nil
}

func isSSLRequest(payload []byte) bool {
	sslCode := []byte{0, 0, 0, 8, 4, 210, 22, 47}
	return bytes.Equal(payload[:8], sslCode)
}

// GetSETChannel implements Honeypot.
func (p *postgresHoneypot) GetSETChannel() <-chan types.Set {
	return p.setChan
}

func NewPostgres(config PostgresConfig) Honeypot {
	return &postgresHoneypot{
		port:    config.Port,
		setChan: make(chan types.Set),
	}
}

// searchUsername string ,which places behind "user" in the payload
func searchUsername(payload []byte) string {
	//calculate the length of the username-length of payload without:68
	//It should be divided by 2 because username is written twice in the payload
	databaseIndex := bytes.LastIndex(payload, []byte("database"))

	//search for "user" in the payload
	userIndex := bytes.Index(payload, []byte("user"))
	if userIndex == -1 {
		return ""
	}
	if databaseIndex < userIndex {
		return ""
	}
	startIndex := userIndex + 5
	username := payload[startIndex : databaseIndex-1]
	return string(username)
}

func pwAuthResponse() []byte {
	buf := []byte{82, 0, 0, 0, 0}
	pos := 1
	// cleartext
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(3))
	buf = append(buf, x...)

	// wrap
	p := buf[pos:]
	binary.BigEndian.PutUint32(p, uint32(len(p)))
	return buf

}

func authErrorResponse() []byte {
	buf := []byte{'E', 0, 0, 0, 0}
	pos := 1
	// Severity
	buf = append(buf, ("SERROR" + "\000")...)
	// Code & Position
	buf = append(buf, ("C08P01" + "\000")...)
	// Message
	buf = append(buf, ("M" + "Authentication failed" + "\000" + "\000")...)
	p := buf[pos:]
	binary.BigEndian.PutUint32(p, uint32(len(p)))
	return buf
}

func isPasswordMessage(msg []byte) bool {
	return strings.HasPrefix(string(msg), "p")
}

func isLoginMessage(msg []byte) bool {
	// create a string representation of the message
	msgStr := string(msg)
	// if there is the word "user" and "database" in the message, we can be sure, that
	// this is the initial connection message
	return strings.Contains(msgStr, "user") && strings.Contains(msgStr, "database")
}
