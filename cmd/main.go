package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/l3montree-dev/oh-my-honeypot/packages/dbip"
	"github.com/l3montree-dev/oh-my-honeypot/packages/honeypot"
	"github.com/l3montree-dev/oh-my-honeypot/packages/pipeline"
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"

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
		slog.Warn("Error loading .env file", "err", err)
	}

	postgresqlDB := store.PostgreSQL{}
	err = postgresqlDB.Start(
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"),
	)
	if err != nil {
		panic(err)
	}

	// start a cron job to clean the database
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			slog.Info("Starting cron job to clean the database")
			postgresqlDB.DeleteEverythingBefore(time.Now().AddDate(0, 0, -8))
			slog.Info("Cron job finished")
		}
	}()

	httpHoneypot := honeypot.NewHTTP(honeypot.HTTPConfig{
		Port: 80,
		HTTPSConfig: honeypot.HTTPSConfig{
			Port:     443,
			CertFile: "cert.pem",
			KeyFile:  "key.pem",
		},
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
	// udpHoneypot := honeypot.NewUDP(honeypot.MostUsedUDPPorts())

	err = tcpHoneypot.Start()
	if err != nil {
		panic(err)
	}

	// err = udpHoneypot.Start()
	// if err != nil {
	// 	panic(err)
	// }

	httpTransport := transport.NewHTTP(transport.HTTPConfig{
		Port: 1112,
		// initializes the http transport with the fifo store
		Getter:       &postgresqlDB,
		RealtimeChan: make(chan types.Set),
	})

	httpTransport.Listen()
	dbChan := postgresqlDB.Listen()

	dbIp := dbip.NewIpToCountry("dbip-country.csv")
	// listen for SET events
	setChannel :=
		pipeline.Map(
			pipeline.Merge(
				sshHoneypot.GetSETChannel(),
				httpHoneypot.GetSETChannel(),
				tcpHoneypot.GetSETChannel(),
				// udpHoneypot.GetSETChannel(),
				postgresHoneypot.GetSETChannel()),
			func(input types.Set) (types.Set, error) {
				input.COUNTRY = dbIp.Lookup(net.ParseIP(input.SUB))
				input.HONEYPOT = string(os.Getenv("HONEYPOT_NAME"))
				return input, nil
			})
	// save everything, which is send over the setChannel inside the database
	pipeline.Pipe(setChannel, dbChan)
	dbSubscription := postgresqlDB.SubscribeToDBChanges()

	// broadcast the events to the http transport
	pipeline.Pipe(dbSubscription, httpTransport.RealtimeChan)
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
