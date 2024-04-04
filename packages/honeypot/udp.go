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

func MostUsedUDPPorts() []int {
	return []int{
		67,  // DHCP
		68,  // DHCP
		123, // NTP
		514, // Syslog
	}
}

type udpHoneypot struct {
	ports   []int
	setChan chan set.Token
}

func (h *udpHoneypot) Start() error {
	// create a tcp listener for each port
	// create a goroutine for each listener
	for _, port := range h.ports {
		go func(port int) {
			// create a new tcp listener on the port
			connection, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
			if err != nil {
				slog.Error("error creating UDP listener", "port", port, "err", err)
				return
			}
			defer connection.Close()

			slog.Info("started UDP honeypot", "port", port)

			for {
				buffer := make([]byte, 1024)
				_, conn, _ := connection.ReadFrom(buffer)

				sub, _ := utils.NetAddrToIpStr(conn)
				h.setChan <- set.Token{
					SUB: sub,
					ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot/udp",
					IAT: time.Now().Unix(),
					JTI: uuid.New().String(),
					TOE: time.Now().Unix(),
					Events: map[string]map[string]interface{}{
						"https://gitlab.com/neuland-homeland/honeypot/json-schema/udp-port": {
							"port": fmt.Sprintf("%d", port),
						},
					},
				}

			}
		}(port)
	}
	return nil
}

func (h *udpHoneypot) GetSETChannel() <-chan set.Token {
	return h.setChan
}

func NewUDP(ports []int) Honeypot {
	return &udpHoneypot{
		setChan: make(chan set.Token),
		ports:   ports,
	}
}
