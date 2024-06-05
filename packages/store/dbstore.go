package store

import (
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/l3montree-dev/oh-my-honeypot/packages/honeypot"
	"github.com/l3montree-dev/oh-my-honeypot/packages/set"
	_ "github.com/lib/pq"
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
				timestamp := input.IAT
				if portEvent, ok := input.Events[honeypot.PortEventID]; ok {
					port = portEvent["port"].(int)
					attackType = "Port Scanning"
				}
				if loginEvent, ok := input.Events[honeypot.LoginEventID]; ok {
					port = loginEvent["port"].(int)
					username := loginEvent["username"].(string)
					password := loginEvent["password"].(string)
					service := loginEvent["service"].(string)
					attackType = "Login Attempt"
					defer p.loginAttemptInsert(input.JTI, service, username, password)
				}
				if httpEvent, ok := input.Events[honeypot.HTTPEventID]; ok {
					attackType = "HTTP Request"
					method := httpEvent["method"].(string)
					path := httpEvent["path"].(string)
					port = httpEvent["port"].(int)
					acceptLanguage := httpEvent["accept-lang"].(string)
					useragent := httpEvent["user-agent"].([]string)
					//store the payload if the method is POST, PUT or PATCH
					if method == "POST" || method == "PUT" || method == "PATCH" {
						payload := httpEvent["body"].(string)
						if httpEvent["attack-type"] == "Spam" {
							name := httpEvent["name"].(string)
							email := httpEvent["e-mail"].(string)
							defer p.spamInsert(input.JTI, name, email)
						}
						payloadSize := httpEvent["bodysize"].(int)
						maxSize := int64(100 * 1024 * 1024)
						//store the payload if it is less than 100MB
						if payloadSize < int(maxSize) {
							attackID := input.JTI
							if err := savePayload(attackID, payload); err != nil {
								slog.Warn("could not save payload", "err", err)
							}
						} else {
							slog.Info("Payload size is greater than 100MB")
						}
						//store the content type and payload size
						contentType := httpEvent["content-type"].(string)
						defer p.bodyInsert(input.JTI, contentType, strconv.Itoa(payloadSize)+" bytes")

					}
					defer p.httpInsert(input.JTI, method, path, acceptLanguage, useragent)
				}
				// Insert the basic information about all attacks into the database
				p.attackInsert(input.JTI, input.HONEYPOT, int(timestamp), port, input.SUB, input.COUNTRY, attackType)
			}()
		}
	}()
	return res
}

// Insert the attack into the database and sanitize the input by using prepared statements
func (p *PostgreSQL) attackInsert(attackID string, honeypot_id string, time int, port int, ip string, country string, attackType string) {
	_, err := p.DB.Exec(`
	INSERT INTO attack_log (Attack_id,Honeypot_id, Time_Of_Event,Port_Nr,IP_Address,Country,Attack_Type)
	VALUES ($1, $2, $3, $4,$5, $6, $7);
	`, attackID, honeypot_id, time, port, ip, country, attackType)
	if err != nil {
		log.Println("Error inserting into the database attack_log", err)
	}
}

func (p *PostgreSQL) loginAttemptInsert(attackID string, service string, username string, password string) {
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

func (p *PostgreSQL) bodyInsert(attackID string, contentType string, payloadSize string) {
	_, err := p.DB.Exec(`
	INSERT INTO http_body (Attack_ID,content_type,payload_size)
	VALUES ($1,$2,$3)
	`, attackID, contentType, payloadSize)
	if err != nil {
		//Err
		log.Println("Error inserting into the database http_body", err)
	}
}

func (p *PostgreSQL) spamInsert(attackID string, name string, email string) {
	_, err := p.DB.Exec(`
	INSERT INTO http_spam (Attack_ID,name,email)
	VALUES ($1,$2,$3)
	`, attackID, name, email)
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
		Honeypot_ID TEXT,
		Time_Of_Event INT,
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
		content_type TEXT, 
		payload_size TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID));`)
	if err != nil {
		log.Println("Error creating table http_body", err)
	}
	_, err = p.DB.Exec(`
	CREATE TABLE IF NOT EXISTS http_spam (
		Attack_ID TEXT PRIMARY KEY, 
		name TEXT, 
		email TEXT, 
		message_size TEXT, 
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

func (p *PostgreSQL) GetAttacks() []set.Token {
	// Get all attacks from the last 24 hours
	oneDayAgo := time.Now().Add(-24 * time.Hour).Unix()
	query := "SELECT * FROM attack_log WHERE time_of_event > $1"
	rows, err := p.DB.Query(query, oneDayAgo)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()

	var tokens []set.Token
	for rows.Next() {
		var ip_address, country, attack_id, attack_type string
		var time_of_event int
		var port_nr int
		err := rows.Scan(&attack_id, &time_of_event, &port_nr, &ip_address, &country, &attack_type)
		if err != nil {
			log.Panic(err)
		}
		token := set.Token{
			SUB:     ip_address,
			COUNTRY: country,
			ISS:     "github.com/l3montree-dev/oh-my-honeypot/honeypot/",
			IAT:     int64(time_of_event),
			JTI:     attack_id,
			Events: map[string]map[string]interface{}{
				"properties": {
					"port": port_nr,
				},
			},
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		log.Panic(err)
	}

	return tokens
}
