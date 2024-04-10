package honeypot

import (
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
					//msg := make([]byte, 1024)
					//n, err := conn.Read(msg)
					//fmt.Println(msg[:n], string(msg[:n]), err, n)
					sub, _ := utils.NetAddrToIpStr(conn.RemoteAddr())
					p.setChan <- set.Token{
						SUB: sub,
						ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot/http",
						IAT: time.Now().Unix(),
						JTI: uuid.New().String(),
						TOE: time.Now().Unix(),
						Events: map[string]map[string]interface{}{
							LoginEventID: {
								//"username": c.User(),
								//"password": string(pass),
								"port": p.port,
							},
						},
					}
				}(conn)
			}
		}()

	}()
	return nil
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
