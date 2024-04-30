package main

import (
	"log"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/l3montree-dev/oh-my-honeypot/packages/dbip"
	"github.com/l3montree-dev/oh-my-honeypot/packages/honeypot"
	"github.com/l3montree-dev/oh-my-honeypot/packages/pipeline"
	"github.com/l3montree-dev/oh-my-honeypot/packages/set"
	"github.com/l3montree-dev/oh-my-honeypot/packages/store"
	"github.com/l3montree-dev/oh-my-honeypot/packages/transport"
	"github.com/lmittmann/tint"
)

func main() {
	InitLogger()

	// Load the .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}
	// Get the port from the .env file as integer
	portInt, err := strconv.Atoi(os.Getenv("POSTGRES_PORT"))
	if err != nil {
		panic(err)
	}

	postgresqlDB := store.PostgreSQL{
		Host:     string(os.Getenv("POSTGRES_HOST")),
		Port:     portInt,
		User:     string(os.Getenv("POSTGRES_USER")),
		Password: string(os.Getenv("POSTGRES_PASSWORD")),
		DBName:   string(os.Getenv("POSTGRES_DB")),
	}
	err = postgresqlDB.Start()
	if err != nil {
		panic(err)
	}

	httpHoneypot := honeypot.NewHTTP(honeypot.HTTPConfig{
		Port: 80,
	})
	err = httpHoneypot.Start()
	if err != nil {
		panic(err)
	}

	postgresHoneypot := honeypot.NewPostgres(honeypot.PostgresConfig{
		Port: 5432,
	})
	err = postgresHoneypot.Start()
	if err != nil {
		panic(err)
	}

	sshHoneypot := honeypot.NewSSH(honeypot.SSHConfig{
		Port: 22,
	})
	err = sshHoneypot.Start()
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

	dbChan := postgresqlDB.Listen()

	// listen for SET events
	setChannel := pipeline.Map(pipeline.Merge(sshHoneypot.GetSETChannel(), tcpHoneypot.GetSETChannel(), udpHoneypot.GetSETChannel(), httpHoneypot.GetSETChannel(), postgresHoneypot.GetSETChannel()), func(input set.Token) (set.Token, error) {
		input.COUNTRY = dbIp.Lookup(net.ParseIP(input.SUB))
		return input, nil
	})

	pipeline.Broadcast(setChannel, socketioChan, httpChan, dbChan)
	forever := make(chan bool)
	<-forever
}

func InitLogger() {
	loggingHandler := tint.NewHandler(os.Stdout, &tint.Options{
		AddSource: true,
		Level:     slog.LevelDebug,
	})
	logger := slog.New(loggingHandler)
	slog.SetDefault(logger)
}
