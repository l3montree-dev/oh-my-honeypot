package honeypot

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
	"github.com/l3montree-dev/oh-my-honeypot/packages/utils"
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
	setChan chan types.Set
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
				go func() {
					sub, _ := utils.NetAddrToIpStr(conn)
					h.setChan <- types.Set{
						SUB: sub,
						ISS: "github.com/l3montree-dev/oh-my-honeypot/packages/honeypot/udp",
						IAT: time.Now().Unix(),
						JTI: uuid.New().String(),
						Events: map[string]map[string]interface{}{
							PortEventID: {
								"port": port,
							},
						},
					}
				}()

			}
		}(port)
	}
	return nil
}

func (h *udpHoneypot) GetSETChannel() <-chan types.Set {
	return h.setChan
}

func NewUDP(ports []int) Honeypot {
	return &udpHoneypot{
		setChan: make(chan types.Set),
		ports:   ports,
	}
}
