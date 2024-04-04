package main

import (
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"gitlab.com/neuland-homeland/honeypot/packages/dbip"
	"gitlab.com/neuland-homeland/honeypot/packages/honeypot"
	"gitlab.com/neuland-homeland/honeypot/packages/pipeline"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
	"gitlab.com/neuland-homeland/honeypot/packages/store"
	"gitlab.com/neuland-homeland/honeypot/packages/transport"
)

// InitLogger initializes the logger with a tint handler.
// tint is a simple logging library that allows to add colors to the log output.
// this is obviously not required, but it makes the logs easier to read.
func InitLogger() {
	loggingHandler := tint.NewHandler(os.Stdout, &tint.Options{
		AddSource: true,
		Level:     slog.LevelDebug,
	})
	logger := slog.New(loggingHandler)
	slog.SetDefault(logger)
}

func main() {
	InitLogger()
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
		Port: 1112,
		// initializes the http transport with the lifo store
		Store: fileStore,
	})
	socketioTransport := transport.NewSocketIO(transport.SocketIOConfig{
		Port: 1113,
	})
	httpChan := httpTransport.Listen()
	socketioChan := socketioTransport.Listen()

	dbIp := dbip.NewIpToCountry("dbip-country.csv")

	// listen for SET events
	setChannel := pipeline.Map(pipeline.Merge(sshHoneypot.GetSETChannel(), tcpHoneypot.GetSETChannel(), udpHoneypot.GetSETChannel()), func(input set.Token) (set.Token, error) {
		input.COUNTRY = dbIp.Lookup(net.ParseIP(input.SUB))
		return input, nil
	})

	pipeline.Broadcast(setChannel, httpChan, socketioChan)
	forever := make(chan bool)
	<-forever
}
