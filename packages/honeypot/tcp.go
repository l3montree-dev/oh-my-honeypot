package honeypot

import (
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"gitlab.com/neuland-homeland/honeypot/packages/utils"
)

func MostUsedTCPPorts() []int {
	return []int{
		21,    // FTP
		23,    // Telnet
		25,    // SMTP
		53,    // DNS
		88,    // Kerberos
		110,   // POP3
		143,   // IMAP
		389,   // LDAP
		465,   // SMTPS
		546,   // DHCPv6 Client
		547,   // DHCPv6 Server
		636,   // LDAPS
		989,   // FTPS
		990,   // FTPS
		993,   // IMAPS
		995,   // POP3S
		3306,  // MySQL
		8001,  // kubernetes dashboard default port
		6443,  // kubernetes api server
		2379,  // etcd
		2380,  // etcd
		10250, // kubelet
		10251, // kube-scheduler
		10252, // kube-controller-manager
		10255, // kube-proxy
	}
}

type tcpHoneypot struct {
	ports   []int
	setChan chan set.Token
}

func (h *tcpHoneypot) Start() error {
	// create a tcp listener for each port
	// create a goroutine for each listener
	for _, port := range h.ports {
		go func(port int) {
			// create a new tcp listener on the port
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{
				Port: port,
			})
			if err != nil {
				slog.Error("Error creating TCP listener", "port", port, "err", err)
				return
			}
			defer listener.Close()
			slog.Info("Starting TCP honeypot", "port", port)
			for {
				conn, err := listener.Accept()
				if err != nil {
					slog.Error("Error accepting connection on port", "port", port, "err", err)
					continue
				}
				go func(conn net.Conn) {
					defer conn.Close()

					sub, _ := utils.NetAddrToIpStr(conn.RemoteAddr())
					h.setChan <- set.Token{
						SUB: sub,
						ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot/tcp",
						IAT: time.Now().Unix(),
						JTI: uuid.New().String(),
						TOE: time.Now().Unix(),
						Events: map[string]map[string]interface{}{
							PortEventID: {
								"port": port,
							},
						},
					}
				}(conn)
			}
		}(port)
	}
	return nil
}

func (h *tcpHoneypot) GetSETChannel() <-chan set.Token {
	return h.setChan
}

func NewTCP(ports []int) Honeypot {
	return &tcpHoneypot{
		setChan: make(chan set.Token),
		ports:   ports,
	}
}
