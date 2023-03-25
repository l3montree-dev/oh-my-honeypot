package main

import (
	"gitlab.com/neuland-homeland/honeypot/packages/honeypot"
	"gitlab.com/neuland-homeland/honeypot/packages/pipeline"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"gitlab.com/neuland-homeland/honeypot/packages/store"
	"gitlab.com/neuland-homeland/honeypot/packages/transport"
)

func main() {
	sshHoneypot := honeypot.NewSSH(honeypot.SSHConfig{
		Port: 2022,
	})

	err := sshHoneypot.Start()
	if err != nil {
		panic(err)
	}

	// create a new websocket transport
	websocket := transport.NewWebsocket(transport.WebsocketConfig{
		Port: 1111,
	})
	httpTransport := transport.NewHTTP(transport.HTTPConfig{
		Port:  1112,
		Store: store.NewLIFO[set.Token](1000),
	})
	websocketChan := websocket.Listen()
	httpChan := httpTransport.Listen()

	// listen for SET events
	setChannel := sshHoneypot.GetSETChannel()

	pipeline.Broadcast(setChannel, websocketChan, httpChan)
	forever := make(chan bool)
	<-forever
}
