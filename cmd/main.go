package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/l3montree-dev/oh-my-honeypot/packages/dbip"
	"github.com/l3montree-dev/oh-my-honeypot/packages/honeypot"
	"github.com/l3montree-dev/oh-my-honeypot/packages/pipeline"
	"github.com/l3montree-dev/oh-my-honeypot/packages/set"
	"github.com/l3montree-dev/oh-my-honeypot/packages/store"
	"github.com/l3montree-dev/oh-my-honeypot/packages/transport"
	"github.com/lmittmann/tint"
	"github.com/spf13/viper"
)

func main() {
	InitLogger()
	// Initialize viper
	viper.New()
	viper.AddConfigPath(".")
	viper.SetConfigFile("vuln-config.yaml")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Error on Reading Viper Config")
		panic(err)
	}

	// Load the .env file
	err = godotenv.Load(".env")
	if err != nil {
		slog.Warn("Error loading .env file: %s", err)
	}
	// Get the port from the .env file as integer
	portInt, err := strconv.Atoi(os.Getenv("POSTGRES_PORT"))
	if err != nil {
		panic(err)
	}
	postgresqlDB := store.PostgreSQL{
		Host: string(os.Getenv("POSTGRES_HOST")),
		Port: portInt,
		User: string(os.Getenv("POSTGRES_USER")),
		// checkov:skip=CKV_SECRET_6 // False Positive
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

	httpTransport := transport.NewHTTP(transport.HTTPConfig{
		Port: 1112,
		// initializes the http transport with the fifo store
		Getter:       &postgresqlDB,
		RealtimeChan: make(chan set.Token),
	})

	httpTransport.Listen()
	dbChan := postgresqlDB.Listen()

	dbIp := dbip.NewIpToCountry("dbip-country.csv")
	// listen for SET events
	setChannel := pipeline.Map(pipeline.Merge(sshHoneypot.GetSETChannel(), tcpHoneypot.GetSETChannel(), udpHoneypot.GetSETChannel(), httpHoneypot.GetSETChannel(), postgresHoneypot.GetSETChannel()), func(input set.Token) (set.Token, error) {
		input.COUNTRY = dbIp.Lookup(net.ParseIP(input.SUB))
		return input, nil
	})

	pipeline.Broadcast(setChannel, httpTransport.RealtimeChan, dbChan)
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
