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
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
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

func (p *PostgreSQL) Listen() chan<- types.Set {
	// listen to all tokens passed into the channel
	res := make(chan types.Set)
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
				p.attackInsert(input.JTI, int(timestamp), port, input.SUB, input.COUNTRY, attackType)
			}()
		}
	}()
	return res
}

// Insert the attack into the database and sanitize the input by using prepared statements
func (p *PostgreSQL) attackInsert(attackID string, time int, port int, ip string, country string, attackType string) {
	_, err := p.DB.Exec(`
	INSERT INTO attack_log (Attack_id, Time_Of_Event,Port_Nr,IP_Address,Country,Attack_Type)
	VALUES ($1, $2, $3, $4,$5, $6);
	`, attackID, time, port, ip, country, attackType)
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

// GetAttacksIn24Hours returns attack events in 24hours from DB
func (p *PostgreSQL) GetAttacksIn24Hours() []types.Set {
	// Get all attacks from the last 24 hours
	oneDayAgo := time.Now().Add(-24 * time.Hour).Unix()
	query := `SELECT * FROM attack_log WHERE time_of_event > $1;`
	rows, err := p.DB.Query(query, oneDayAgo)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()

	var tokens []types.Set
	for rows.Next() {
		var ip_address, country, attack_id, attack_type string
		var time_of_event int
		var port_nr int
		err := rows.Scan(&attack_id, &time_of_event, &port_nr, &ip_address, &country, &attack_type)
		if err != nil {
			log.Panic(err)
		}
		token := types.Set{
			SUB:     ip_address,
			COUNTRY: country,
			ISS:     "github.com/l3montree-dev/oh-my-honeypot/honeypot/",
			IAT:     int64(time_of_event),
			JTI:     attack_id,
			Events:  make(map[string]map[string]interface{}),
		}
		if attack_type == "Login Attempt" {
			token.Events[honeypot.LoginEventID] = map[string]interface{}{
				"port": port_nr,
			}
		} else if attack_type == "HTTP Request" {
			token.Events[honeypot.HTTPEventID] = map[string]interface{}{
				"port": port_nr,
			}
		} else if attack_type == "Port Scanning" {
			token.Events[honeypot.PortEventID] = map[string]interface{}{
				"port": port_nr,
			}
		}

		tokens = append(tokens, token)

		if err := rows.Err(); err != nil {
			log.Panic(err)
		}

	}
	return tokens
}

// GetCountIn24Hours returns number of attacks per day for last 7 days from DB
func (p *PostgreSQL) GetCountIn24Hours() []types.CountIn24HoursStats {
	rows, err := p.DB.Query(`
	WITH Hourly_Attacks AS (
		SELECT
			DATE_TRUNC('hour', TO_TIMESTAMP(time_of_event)) AS hour,
			COUNT(*) AS num_attacks
		FROM attack_log
		WHERE TO_TIMESTAMP(time_of_event) >= NOW() - INTERVAL '24 hour'
		GROUP BY DATE_TRUNC('hour', TO_TIMESTAMP(time_of_event))
		ORDER BY hour
	),
	Hourly_Sequence AS (
		SELECT
			generate_series(
				DATE_TRUNC('hour', NOW() - INTERVAL '24 hour'),
				DATE_TRUNC('hour', NOW()),
				'1 hour'
			) AS hour
	)
	SELECT
		TO_CHAR(h.hour, 'HH24') AS hour,
		SUM(COALESCE(a.num_attacks, 0)) OVER (ORDER BY h.hour ASC) AS cumulative_attacks
	FROM
		Hourly_Sequence h
	LEFT JOIN
		Hourly_Attacks a
	ON
		h.hour = a.hour
	ORDER BY
		h.hour;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()
	var tokens []types.CountIn24HoursStats
	for rows.Next() {
		var hour int
		var count int
		err := rows.Scan(&hour, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.CountIn24HoursStats{
			Hour:  string(hour),
			Count: count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}

func (p *PostgreSQL) GetCountIn7Days() []types.CountIn7DaysStats {
	rows, err := p.DB.Query(`
		SELECT TO_CHAR(TO_TIMESTAMP(time_of_event), 'DD/MM') AS date,
		COUNT(*) AS count
		FROM attack_log
		WHERE TO_TIMESTAMP(time_of_event) >= CURRENT_DATE - INTERVAL '7 days'
		GROUP BY TO_CHAR(TO_TIMESTAMP(time_of_event), 'DD/MM')
		ORDER BY date;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()
	var tokens []types.CountIn7DaysStats
	for rows.Next() {
		var date string
		var count int
		err := rows.Scan(&date, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.CountIn7DaysStats{
			Date:  date,
			Count: count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}

func (p *PostgreSQL) GetCountIn6Months() []types.CountIn6MonthsStats {
	rows, err := p.DB.Query(`
		SELECT TO_CHAR(TO_TIMESTAMP(time_of_event), 'MM/YYYY') AS month,
		COUNT(*) AS count
		FROM attack_log
		WHERE TO_TIMESTAMP(time_of_event) >= CURRENT_DATE - INTERVAL '6 months'
		GROUP BY TO_CHAR(TO_TIMESTAMP(time_of_event), 'MM/YYYY')
		ORDER BY month;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()
	var tokens []types.CountIn6MonthsStats
	for rows.Next() {
		var month string
		var count int
		err := rows.Scan(&month, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.CountIn6MonthsStats{
			Month: month,
			Count: count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}

func (p *PostgreSQL) GetCountryStats() []types.CountryStats {
	rows, err := p.DB.Query(`
		SELECT attack_log.country, COUNT(attack_log.country) AS count
		FROM attack_log
		GROUP BY attack_log.country
		ORDER BY COUNT(attack_log.country) 
		DESC ;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()
	var tokens []types.CountryStats
	for rows.Next() {
		var country string
		var count int
		err := rows.Scan(&country, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.CountryStats{
			Country: country,
			Count:   count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}

func (p *PostgreSQL) GetIPStats() []types.IPStats {
	rows, err := p.DB.Query(`
		SELECT attack_log.ip_address, attack_log.country, COUNT(attack_log.ip_address) AS count
		FROM attack_log
		GROUP BY attack_log.ip_address, attack_log.country
		ORDER BY COUNT(attack_log.ip_address) 
		DESC;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()

	var tokens []types.IPStats
	for rows.Next() {
		var ip_address, country string
		var count int
		err := rows.Scan(&ip_address, &country, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.IPStats{
			IP:      ip_address,
			Country: country,
			Count:   count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}

func (p *PostgreSQL) GetUsernameStats() []types.UsernameStats {
	rows, err := p.DB.Query(`
		SELECT login_attempt.username, COUNT(login_attempt.username) AS count
		FROM login_attempt
		GROUP BY login_attempt.username
		ORDER BY COUNT(login_attempt.username) 
		DESC ;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()
	var tokens []types.UsernameStats
	for rows.Next() {
		var username string
		var count int
		err := rows.Scan(&username, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.UsernameStats{
			Username: username,
			Count:    count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}
func (p *PostgreSQL) GetPasswordStats() []types.PasswordStats {
	rows, err := p.DB.Query(`
		SELECT login_attempt.password, COUNT(login_attempt.password) AS count
		FROM login_attempt
		GROUP BY login_attempt.password
		ORDER BY COUNT(login_attempt.password) 
		DESC ;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()

	var tokens []types.PasswordStats
	for rows.Next() {
		var password string
		var count int
		err := rows.Scan(&password, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.PasswordStats{
			Password: password,
			Count:    count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}

func (p *PostgreSQL) GetPortStats() []types.PortStats {
	rows, err := p.DB.Query(`
		SELECT attack_log.port_nr, COUNT(attack_log.port_nr) AS count
		FROM attack_log
		GROUP BY attack_log.port_nr
		ORDER BY COUNT(attack_log.port_nr) 
		DESC ;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()

	var tokens []types.PortStats
	for rows.Next() {
		var count, port_nr int
		err := rows.Scan(&port_nr, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.PortStats{
			Port:  string(port_nr),
			Count: count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}

func (p *PostgreSQL) GetPathStats() []types.PathStats {
	rows, err := p.DB.Query(`
		SELECT http_request.path, COUNT(http_request.path) AS count
		FROM http_request
		GROUP BY http_request.path
		ORDER BY COUNT(http_request.path) 
		DESC ;
		`)
	if err != nil {
		log.Panic(err)
	}
	defer rows.Close()

	var tokens []types.PathStats
	for rows.Next() {
		var path string
		var count int
		err := rows.Scan(&path, &count)
		if err != nil {
			log.Panic(err)
		}
		res := types.PathStats{
			Path:  path,
			Count: count,
		}
		tokens = append(tokens, res)
	}
	if err := rows.Err(); err != nil {
		log.Panic(err)
	}
	return tokens
}
