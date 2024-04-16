package honeypot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"gitlab.com/neuland-homeland/honeypot/packages/utils"
)

type postgresHoneypot struct {
	port int
	// setChan is the channel the honeypot is posting SET events to.
	setChan chan set.Token
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

					msg := make([]byte, 1024)
					n, err := conn.Read(msg)
					if err != nil {
						slog.Error("failed to read from connection", "err", err)
						return
					}
					if isSSLRequest(msg[:n]) {
						fmt.Println("SSL request received")
						conn.Write([]byte("N"))
						conn.Close()
						return
					}
					username := searchUsername(msg[:n])
					conn.Write(pwAuthResponse())
					n, err = conn.Read(msg)
					if err != nil {
						slog.Error("failed to read from connection", "err", err)
						return
					}
					password := msg[:n]
					conn.Close()

					//response that the password is not correct

					sub, _ := utils.NetAddrToIpStr(conn.RemoteAddr())
					p.setChan <- set.Token{
						SUB: sub,
						ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot/http",
						IAT: time.Now().Unix(),
						JTI: uuid.New().String(),
						TOE: time.Now().Unix(),
						Events: map[string]map[string]interface{}{
							LoginEventID: {
								"username": username,
								"password": password,
								"port":     p.port,
							},
						},
					}
				}(conn)
			}
		}()

	}()
	return nil
}

//func (p *postgresHoneypot) handleAuth() error {

func isSSLRequest(payload []byte) bool {
	sslCode := []byte{0, 0, 0, 8, 4, 210, 22, 47}
	return bytes.Equal(payload[:8], sslCode)
}

// GetSETChannel implements Honeypot.
func (p *postgresHoneypot) GetSETChannel() <-chan set.Token {
	return p.setChan
}

func NewPostgres(config PostgresConfig) Honeypot {
	return &postgresHoneypot{
		port:    config.Port,
		setChan: make(chan set.Token),
	}
}

// searchUsername string ,which places between "user" and "database" in the payload
func searchUsername(payload []byte) string {
	//search for "user" in the payload
	userIndex := bytes.Index(payload, []byte("user"))
	if userIndex == -1 {
		return ""
	}
	//search for "database" in the payload
	databaseIndex := bytes.Index(payload, []byte("database"))
	if databaseIndex == -1 {
		return ""
	}
	//search for the username between "user" and "database"
	username := payload[userIndex+5 : databaseIndex-1]
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
