package main

import "gitlab.com/neuland-homeland/honeypot/packages/honeypot"

func main() {
	sshHoneypot := honeypot.NewSSH(honeypot.SSHConfig{
		Port: 2022,
	})

	sshHoneypot.Start()
}
