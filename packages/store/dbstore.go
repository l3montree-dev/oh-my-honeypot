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
	// listen to all tokens passed into the channel
	res := make(chan set.Token)
	go func() {
		for input := range res {
			go func() {
				var port int
				var attackType string
				timestamp := int64(input.TOE)
				timeObj := time.Unix(timestamp, 0)
				if input.Events[honeypot.PortEventID] != nil {
					port = input.Events[honeypot.PortEventID]["port"].(int)
					attackType = "Port Scanning"
				}
				if input.Events[honeypot.LoginEventID] != nil {
					attackType = "Login Attempt"
					port = input.Events[honeypot.LoginEventID]["port"].(int)
					defer p.logininfoInsert(input.JTI, input.Events[honeypot.LoginEventID]["username"].(string), input.Events[honeypot.LoginEventID]["password"].(string))
				}
				if input.Events[honeypot.HTTPEventID] != nil {
					attackType = "HTTP Request"
					port = input.Events[honeypot.HTTPEventID]["port"].(int)
					defer p.httpInsert(input.JTI, input.Events[honeypot.HTTPEventID]["accept-lang"].(string), input.Events[honeypot.HTTPEventID]["user-agent"].([]string))
				}
				p.attackInsert(input.JTI, timeObj, port, input.SUB, input.COUNTRY, attackType)
			}()
		}
	}()
	return res
}

func (p *PostgreSQL) attackInsert(attackID string, time time.Time, port int, ip string, country string, attackType string) {
	_, err := p.DB.Exec(`
	INSERT INTO attack_log (Attack_id, Time_Of_Event,Port_Nr,IP_Address,Country,Attack_Type)
	VALUES ($1, $2, $3, $4,$5, $6);
	`, attackID, time, port, ip, country, attackType)

	if err != nil {
		log.Println("Error while storing on the DB", err)
	}
}

func (p *PostgreSQL) logininfoInsert(attackID string, username string, password string) {
	_, err := p.DB.Exec(`
	INSERT INTO login_attempt (Attack_ID,Username,Password)
	VALUES ($1, $2, $3)
	`, attackID, username, password)

	if err != nil {
		log.Println("Error while storing on the DB", err)
	}
}

func (p *PostgreSQL) httpInsert(attackID string, acceptLanguage string, useragent []string) {
	_, err := p.DB.Exec(`
	INSERT INTO http_request (Attack_ID,accept_language,system,rendering_engine,platform)
	VALUES ($1, $2, $3, $4, $5)
	`, attackID, acceptLanguage, useragent[0], useragent[1], useragent[2])

	if err != nil {
		log.Println("Error while storing on the DB", err)
	}
}

// Start initializes the PostgreSQL database connection.
func (p *PostgreSQL) Start() error {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		p.Host, p.Port, p.User, p.Password, p.DBName)

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Println("Error while opening to the DB", err)
		return err
	}

	// Set the database connection in the postgreSQL struct
	p.DB = db

	// Create the tables if they do not exist
	_, err = p.DB.Exec(`
		CREATE TABLE IF NOT EXISTS attack_log (
			Attack_ID TEXT PRIMARY KEY,
			Time_Of_Event TIMESTAMP,
			Port_Nr INT,
			IP_Address TEXT,
			Country TEXT,
			Attack_Type TEXT
			);
		CREATE TABLE IF NOT EXISTS login_attempt (
			Attack_ID TEXT PRIMARY KEY,
			Username TEXT,
			Password TEXT,
			FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID) 
			);
		CREATE TABLE IF NOT EXISTS http_request (
			Attack_ID TEXT PRIMARY KEY,
			accept_language TEXT,
			system	TEXT,
			rendering_engine TEXT,
			platform TEXT,
			FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID) 
			);
			`)
	if err != nil {
		log.Println("Error while creating tables", err)
	}
	slog.Info("PostgreSQL store started")

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
