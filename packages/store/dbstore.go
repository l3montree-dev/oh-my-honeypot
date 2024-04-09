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
				var attackType string
				var port interface{}
				timestamp := int64(input.TOE)
				timeObj := time.Unix(timestamp, 0)
				for _, event := range input.Events {
					for key, value := range event {
						if key == "port" {
							port = fmt.Sprintf("%v", value)
							break
						}
					}
					if port != "" {
						break
					}
				}
				attackType = "Port Scanning"
				if input.Events[honeypot.LoginEventID] != nil {
					attackType = "Login Attempt"
				}
				_, err := p.DB.Exec(`
				INSERT INTO attack_log (Attack_id, Time_Of_Event,Port_Nr,IP_Address,Country,Attack_Type)
				VALUES ($1, $2, $3, $4,$5,$6);
				`, input.JTI, timeObj, port, input.SUB, input.COUNTRY, attackType)

				if err != nil {
					log.Println("Error while storing on the DB", err)
				}

				if input.Events[honeypot.LoginEventID] != nil {
					_, err := p.DB.Exec(`
					INSERT INTO login_attempt (Attack_ID,Username,Password)
					VALUES ($1, $2, $3)
					`, input.JTI, input.Events[honeypot.LoginEventID]["username"], input.Events[honeypot.LoginEventID]["password"])

					if err != nil {
						log.Println("Error while storing on the DB", err)
					}
				}

			}()
		}
	}()

	return res
}

func (p *PostgreSQL) Insert(input set.Token) error {
	return nil
}

func (p *PostgreSQL) GetAttackLogs() ([]map[string]interface{}, error) {
	rows, err := p.DB.Query(`
	SELECT * FROM attack_log;
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []map[string]interface{}
	for rows.Next() {
		var attackID int
		var timeOfEvent time.Time
		var portNr int
		var ipAddress string
		var country string
		var attackType string
		err := rows.Scan(&attackID, &timeOfEvent, &portNr, &ipAddress, &country, &attackType)
		if err != nil {
			return nil, err
		}
		logs = append(logs, map[string]interface{}{
			"Attack_ID":     attackID,
			"Time_Of_Event": timeOfEvent,
			"Port_Nr":       portNr,
			"IP_Address":    ipAddress,
			"Country":       country,
			"Attack_Type":   attackType,
		})
	}
	return logs, nil
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
