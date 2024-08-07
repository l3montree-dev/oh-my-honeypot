package honeypot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
	"github.com/l3montree-dev/oh-my-honeypot/packages/utils"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type sshHoneypot struct {
	port int
	// setChan is the channel the honeypot is posting SET events to.
	setChan chan types.Set
}
type SSHConfig struct {
	Port int
}

func (s *sshHoneypot) Start() error {
	config := &ssh.ServerConfig{
		//Define a function to run when a client attempts a password login
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// always return an error - just log the username and password
			sub, _ := utils.NetAddrToIpStr(c.RemoteAddr())
			s.setChan <- types.Set{
				SUB: sub,
				ISS: "github.com/l3montree-dev/oh-my-honeypot/packages/honeypot/ssh",
				IAT: time.Now().Unix(),
				JTI: uuid.New().String(),
				Events: map[string]map[string]interface{}{
					LoginEventID: {
						"username": c.User(),
						"password": string(pass),
						"port":     s.GetPort(),
						"service":  "ssh",
					},
				},
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	//Vulnerable ssh version to attract attackers
	config.ServerVersion = viper.GetString("ssh.ServerVersion")

	privateBytes := encodePrivateKeyToPEM(generatePrivateKey())
	private, err := ssh.ParsePrivateKey(privateBytes)

	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:"+fmt.Sprintf("%d", s.port))
	if err != nil {
		log.Fatalf("Failed to listen on %d (%s)", s.port, err)
	}

	// Accept all connections
	slog.Info("SSH Honeypot started", "port", s.port)
	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				slog.Error("failed to accept incoming connection", "err", err)
				continue
			}
			go s.handeConn(tcpConn, config)
		}
	}()
	return nil
}

func (s *sshHoneypot) handeConn(tcpConn net.Conn, config *ssh.ServerConfig) {
	// just perform the handshake
	defer tcpConn.Close()
	_, _, _, err := ssh.NewServerConn(tcpConn, config)
	sub, _ := utils.NetAddrToIpStr(tcpConn.RemoteAddr())
	//send the token for port scanning attack
	s.setChan <- types.Set{
		SUB: sub,
		ISS: "github.com/l3montree-dev/oh-my-honeypot/packages/honeypot/ssh",
		IAT: time.Now().Unix(),
		JTI: uuid.New().String(),
		Events: map[string]map[string]interface{}{
			PortEventID: {
				"port": s.GetPort(),
			},
		},
	}
	if err != nil {
		return
	}
}

func (s *sshHoneypot) GetPort() int {
	return s.port
}

func (s *sshHoneypot) GetSETChannel() <-chan types.Set {
	return s.setChan
}

func generatePrivateKey() *rsa.PrivateKey {
	// generate a private key
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("Failed to generate private key", "err", err)
	}
	return private
}

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}
func NewSSH(config SSHConfig) Honeypot {
	return &sshHoneypot{
		port:    config.Port,
		setChan: make(chan types.Set),
	}
}
