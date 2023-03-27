package main

import (
	"net"
	"os"
	"time"

	"gitlab.com/neuland-homeland/honeypot/packages/dbip"
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

	tcpHoneypot := honeypot.NewTCP(honeypot.MostUsedTCPPorts())
	udpHoneypot := honeypot.NewUDP(honeypot.MostUsedUDPPorts())

	err = tcpHoneypot.Start()
	if err != nil {
		panic(err)
	}

	err = udpHoneypot.Start()
	if err != nil {
		panic(err)
	}

	lifoStore := store.NewTimeLifo[set.Token](time.Duration(24 * time.Hour))
	// create a file decorator to persist the data
	file, err := os.OpenFile("events.log", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}

	fileStore := store.NewFileDecorator[set.Token](
		file,
		store.NewJSONSerializer[set.Token](),
		lifoStore,
	)

	httpTransport := transport.NewHTTP(transport.HTTPConfig{
		Port:  1112,
		Store: fileStore,
	})

	httpChan := httpTransport.Listen()

	dbIp := dbip.NewIpToCountry("dbip-country.csv")

	// listen for SET events
	setChannel := pipeline.Map(pipeline.Merge(sshHoneypot.GetSETChannel(), pipeline.Aggregate(tcpHoneypot.GetSETChannel(), time.Duration(2*time.Second), honeypot.DetectPortScan), udpHoneypot.GetSETChannel()), func(input set.Token) (set.Token, error) {
		input.COUNTRY = dbIp.Lookup(net.ParseIP(input.SUB))
		return input, nil
	})

	pipeline.Broadcast(setChannel, httpChan)
	forever := make(chan bool)
	<-forever
}
