package honeypot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/uuid"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"gitlab.com/neuland-homeland/honeypot/packages/utils"
	"golang.org/x/crypto/ssh"
)

type sshHoneypot struct {
	port int
	// setChan is the channel the honeypot is posting SET events to.
	setChan chan set.Token
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
			s.setChan <- set.Token{
				SUB: sub,
				ISS: "gitlab.com/neuland-homeland/honeypot/packages/honeypot/ssh",
				IAT: time.Now().Unix(),
				JTI: uuid.New().String(),
				TOE: time.Now().Unix(),
				Events: map[string]map[string]interface{}{
					SSHEventID: {
						"username": c.User(),
						"password": string(pass),
					},
				},
			}
			log.Println("Login attempt:", c.User(), string(pass), c.RemoteAddr())
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

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
	log.Printf("SSH Honeypot started on %d...", s.port)
	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept incoming connection (%s)", err)
				continue
			}

			go handeConn(tcpConn, config)
		}
	}()
	return nil
}

func handeConn(tcpConn net.Conn, config *ssh.ServerConfig) {
	// just perform the handshake
	_, _, _, err := ssh.NewServerConn(tcpConn, config)
	if err != nil {
		return
	}
}

func (s *sshHoneypot) Stop() error {
	return nil
}

func (s *sshHoneypot) GetPort() int {
	return s.port
}

func (s *sshHoneypot) GetSETChannel() <-chan set.Token {
	return s.setChan
}

func generatePrivateKey() *rsa.PrivateKey {
	// generate a private key
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
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
		setChan: make(chan set.Token),
	}
}
