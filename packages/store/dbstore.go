package store

import (
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"
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
					username := input.Events[honeypot.LoginEventID]["username"].(string)
					password := input.Events[honeypot.LoginEventID]["password"].(string)
					service := input.Events[honeypot.LoginEventID]["service"].(string)
					defer p.loginattInsert(input.JTI, service, username, password)
				}
				if input.Events[honeypot.HTTPEventID] != nil {
					attackType = "HTTP Request"
					method := input.Events[honeypot.HTTPEventID]["method"].(string)
					path := input.Events[honeypot.HTTPEventID]["path"].(string)
					port = input.Events[honeypot.HTTPEventID]["port"].(int)
					acceptLanguage := input.Events[honeypot.HTTPEventID]["accept-lang"].(string)
					useragent := input.Events[honeypot.HTTPEventID]["user-agent"].([]string)
					if method == "POST" || method == "PUT" || method == "PATCH" {
						payloadSize := input.Events[honeypot.HTTPEventID]["bodysize"].(int)
						maxSize := int64(100 * 1024 * 1024)
						//Payload size should be greater than 100MB
						if payloadSize < int(maxSize) {
							attackID := input.JTI
							payload := input.Events[honeypot.HTTPEventID]["body"].(string)
							savePayload(attackID, payload)
						} else {
							slog.Info("Payload size is greater than 100MB")
						}
						contentType := input.Events[honeypot.HTTPEventID]["content-type"].(string)
						defer p.bodyInsert(input.JTI, method, contentType, strconv.Itoa(payloadSize)+" bytes")
					}
					defer p.httpInsert(input.JTI, method, path, acceptLanguage, useragent)
				}
				p.attackInsert(input.JTI, timeObj, port, input.SUB, input.COUNTRY, attackType)
			}()
		}
	}()
	return res
}

// Insert the attack into the database and sanitize the input by using prepared statements
func (p *PostgreSQL) attackInsert(attackID string, time time.Time, port int, ip string, country string, attackType string) {
	_, err := p.DB.Exec(`
	INSERT INTO attack_log (Attack_id, Time_Of_Event,Port_Nr,IP_Address,Country,Attack_Type)
	VALUES ($1, $2, $3, $4,$5, $6);
	`, attackID, time, port, ip, country, attackType)
	if err != nil {
		log.Println("Error inserting into the database attack_log", err)
	}
}

func (p *PostgreSQL) loginattInsert(attackID string, service string, username string, password string) {
	_, err := p.DB.Exec(`
	INSERT INTO login_attempt (Attack_ID,service,Username,Password)
	VALUES ($1, $2, $3,$4)
	`, attackID, service, username, password)
	if err != nil {
		log.Println("Error inserting into the database login_attempt", err)
	}
}

func (p *PostgreSQL) httpInsert(attackID string, method string, path string, acceptLanguage string, useragent []string) {
	_, err := p.DB.Exec(`
	INSERT INTO http_request (Attack_ID,method,path,accept_language,system,rendering_engine,platform)
	VALUES ($1, $2, $3, $4, $5, $6,$7)
	`, attackID, method, path, acceptLanguage, useragent[0], useragent[1], useragent[2])
	if err != nil {
		log.Println("Error inserting into the database http_request", err)
	}
}

func (p *PostgreSQL) bodyInsert(attackID string, method string, contentType string, payloadSize string) {
	_, err := p.DB.Exec(`
	INSERT INTO http_body (Attack_ID,method,content_type,payload_size)
	VALUES ($1,$2,$3,$4)
	`, attackID, method, contentType, payloadSize)
	if err != nil {
		//Err
		log.Println("Error inserting into the database http_body", err)
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

	//Create the tables if they do not exist
	_, err = p.DB.Exec(`
	CREATE TABLE IF NOT EXISTS attack_log (
		Attack_ID TEXT PRIMARY KEY,
		Time_Of_Event TIMESTAMP,
		Port_Nr INT,
		IP_Address TEXT,
		Country TEXT,
		Attack_Type TEXT
		);`)
	if err != nil {
		log.Println("Error creating table attack_log", err)
	}
	_, err = p.DB.Exec(`
	CREATE TABLE IF NOT EXISTS login_attempt (
		Attack_ID TEXT PRIMARY KEY, 
		Service TEXT, Username TEXT, 
		Password TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID)
		);`)
	if err != nil {
		log.Println("Error creating table login_attempt", err)
	}
	_, err = p.DB.Exec(`
	CREATE TABLE IF NOT EXISTS http_request (
		Attack_ID TEXT PRIMARY KEY, 
		method TEXT, 
		path TEXT, 
		accept_language TEXT, 
		system TEXT, 
		rendering_engine TEXT, 
		platform TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID)
		);`)
	if err != nil {
		log.Println("Error creating table http_request", err)
	}
	_, err = p.DB.Exec(`
	CREATE TABLE IF NOT EXISTS http_body (
		Attack_ID TEXT PRIMARY KEY, 
		method TEXT, 
		content_type TEXT, 
		payload_size TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID));`)
	if err != nil {
		log.Println("Error creating table http_body", err)
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

func savePayload(id string, payload string) error {
	file, err := os.OpenFile("payloads/"+id, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	_, err = file.WriteString(payload)
	if err != nil {
		panic(err)
	}
	return nil
}
