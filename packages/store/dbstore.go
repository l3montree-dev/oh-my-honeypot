package store

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
	"gitlab.com/neuland-homeland/honeypot/packages/honeypot"
	"gitlab.com/neuland-homeland/honeypot/packages/set"
)

type PostgreSQL struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	DB       *sql.DB
}

func (p *PostgreSQL) DBStore(output <-chan set.Token) error {
	go func() {
		for input := range output {
			timestamp := int64(input.TOE)
			timeObj := time.Unix(timestamp, 0)
			port := input.Events[honeypot.PortEventID]["port"]
			_, err := p.DB.Exec(`
				INSERT INTO udp_tcp (PortNr, IPAddress, Country, TimeOfEvent)
				VALUES ($1, $2, $3, $4);
			`, port, input.SUB, input.COUNTRY, timeObj)
			if err != nil {
				log.Println("Error while storing on the DB", err)
			}
		}
	}()

	return nil
}

// Start initializes the PostgreSQL database connection.
func (p *PostgreSQL) Start() error {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		p.Host, p.Port, p.User, p.Password, p.DBName)

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	// Verify that the connection to the database is working
	err = db.Ping()
	if err != nil {
		log.Println("Error while storing on the DB", err)
		return err
	}

	// Set the database connection in the postgreSQL struct
	p.DB = db

	return nil
}

// Close closes the PostgreSQL database connection.
func (p *PostgreSQL) Close() error {
	// Close the database connection
	if p.DB != nil {
		return p.DB.Close()
	}
	return nil
}
