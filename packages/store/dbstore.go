package store

import (
	"database/sql"
	"fmt"
	"log"
	"log/slog"
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

func (p *PostgreSQL) Listen() chan<- set.Token {
	res := make(chan set.Token)
	// listen to all tokens passed into the channel
	go func() {
		for input := range res {
			go func() {
				var port interface{}
				timestamp := int64(input.TOE)
				timeObj := time.Unix(timestamp, 0)
				if input.Events[honeypot.LoginEventID] == nil {
					port = input.Events[honeypot.PortEventID]["port"]
				}
				if input.Events[honeypot.PortEventID] == nil {
					port = input.Events[honeypot.LoginEventID]["port"]
				}
				_, err := p.DB.Exec(`
						INSERT INTO port_scanning (TimeOfEvent,PortNr,IPAddress,Country)
						VALUES ($1, $2, $3, $4);
					`, timeObj, port, input.SUB, input.COUNTRY)
				if err != nil {
					log.Println("Error while storing on the DB", err)
				}
				if input.Events[honeypot.LoginEventID] != nil {
					_, err = p.DB.Exec(`
						INSERT INTO login_try (Username,Password)
						VALUES ($1, $2);
					`, input.Events[honeypot.LoginEventID]["username"], input.Events[honeypot.LoginEventID]["password"])
					if err != nil {
						log.Println("Error while storing on the DB", err)
					}

				}

			}()
		}
	}()

	return res
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
		log.Println("Error while connecting to the DB", err)
		return err
	}
	// Set the database connection in the postgreSQL struct
	p.DB = db
	//Check if the table exists

	go func() {
		_, err := p.DB.Exec(`
		CREATE TABLE IF NOT EXISTS port_scanning (
			ID SERIAL PRIMARY KEY,
			TimeOfEvent TIMESTAMP,
			PortNr INT,
			IPAddress TEXT,
			Country TEXT,
			AttackType TEXT
		);
		CREATE TABLE IF NOT EXISTS login_try (
			Attack_ID SERIAL PRIMARY KEY,
			Username TEXT,
			Password TEXT
		);
	`)
		if err != nil {
			log.Println("Error while creating tables", err)
		}
		slog.Info("PostgreSQL store started")
	}()
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
