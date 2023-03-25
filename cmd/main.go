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

	portHoneypot := honeypot.NewHttpPort([]int{
		80,
		443,
		8001, // kubernetes dashboard default port
		8080,
		6443,  // kubernetes api server
		2379,  // etcd
		2380,  // etcd
		10250, // kubelet
		10251, // kube-scheduler
		10252, // kube-controller-manager
		10255, // kube-proxy
	})

	err = portHoneypot.Start()
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
	setChannel := pipeline.Merge(sshHoneypot.GetSETChannel(), portHoneypot.GetSETChannel())

	pipeline.Broadcast(setChannel, websocketChan, httpChan)
	forever := make(chan bool)
	<-forever
}
