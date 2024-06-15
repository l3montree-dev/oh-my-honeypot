package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"

	"github.com/l3montree-dev/oh-my-honeypot/packages/honeypot"
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
	_ "github.com/lib/pq"
	"golang.org/x/sync/errgroup"
)

type PostgreSQL struct {
	Host        string
	Port        int
	User        string
	Password    string
	DBName      string
	DB          *sql.DB
	honeypotIDs []string
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
		slog.Error("Error inserting into the database attack_log", "err", err)
	}
}

func (p *PostgreSQL) loginAttemptInsert(attackID string, service string, username string, password string) {
	_, err := p.DB.Exec(`
	INSERT INTO login_attempt (Attack_ID,service,Username,Password)
	VALUES ($1, $2, $3,$4)
	`, attackID, service, username, password)
	if err != nil {
		slog.Error("Error inserting into the database login_attempt", "err", err)
	}
}

func (p *PostgreSQL) httpInsert(attackID string, method string, path string, acceptLanguage string, useragent []string) {
	_, err := p.DB.Exec(`
	INSERT INTO http_request (Attack_ID,method,path,accept_language,system,rendering_engine,platform)
	VALUES ($1, $2, $3, $4, $5, $6,$7)
	`, attackID, method, path, acceptLanguage, useragent[0], useragent[1], useragent[2])
	if err != nil {
		slog.Error("Error inserting into the database http_request", "err", err)
	}
}

func (p *PostgreSQL) bodyInsert(attackID string, contentType string, payloadSize string) {
	_, err := p.DB.Exec(`
	INSERT INTO http_body (Attack_ID,content_type,payload_size)
	VALUES ($1,$2,$3)
	`, attackID, contentType, payloadSize)
	if err != nil {
		slog.Error("Error inserting into the database http_body", "err", err)
	}
}

func (p *PostgreSQL) spamInsert(attackID string, name string, email string) {
	_, err := p.DB.Exec(`
	INSERT INTO http_spam (Attack_ID,name,email)
	VALUES ($1,$2,$3)
	`, attackID, name, email)
	if err != nil {
		slog.Error("Error inserting into the database http_spam", "err", err)
	}
}

// Start initializes the PostgreSQL database connection.
func (p *PostgreSQL) Start() error {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		p.Host, p.Port, p.User, p.Password, p.DBName)

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		slog.Error("Error opening the database connection", "err", err)
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
		slog.Error("Error creating table attack_log", "err", err)
	}
	_, err = p.DB.Exec(`
	CREATE TABLE IF NOT EXISTS login_attempt (
		Attack_ID TEXT PRIMARY KEY, 
		Service TEXT, Username TEXT, 
		Password TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID)
		);`)
	if err != nil {
		slog.Error("Error creating table login_attempt", "err", err)
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
		slog.Error("Error creating table http_request", "err", err)
	}
	_, err = p.DB.Exec(`
	CREATE TABLE IF NOT EXISTS http_body (
		Attack_ID TEXT PRIMARY KEY, 
		content_type TEXT, 
		payload_size TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID));`)
	if err != nil {
		slog.Error("Error creating table http_body", "err", err)
	}
	_, err = p.DB.Exec(`
	CREATE TABLE IF NOT EXISTS http_spam (
		Attack_ID TEXT PRIMARY KEY, 
		name TEXT, 
		email TEXT, 
		message_size TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID));`)
	if err != nil {
		slog.Error("Error creating table http_spam", "err", err)
	}
	_, err = p.DB.Exec(`
	CREATE INDEX attacklog_timestamp_hpid
	ON attack_log(honeypot_id, TO_TIMESTAMP(time_of_event));`)
	if err != nil {
		slog.Error("Error creating table http_spam", "err", err)
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
		slog.Error("could not open file", "err", err)
	}
	defer file.Close()

	_, err = file.WriteString(payload)
	if err != nil {
		slog.Error("could not write to file", "err", err)
	}
	return nil
}

func (p *PostgreSQL) GetCountIn24HoursByCountry() types.CountIn24HoursByCountryResponse {
	var idRes types.CountIn24HoursByCountryResponse = types.CountIn24HoursByCountryResponse{}
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
       SELECT attack_log.country, 
       COUNT(attack_log.country), 
       EXTRACT(HOUR FROM (TO_TIMESTAMP(time_of_event) AT TIME ZONE 'UTC' AT TIME ZONE 'Europe/Berlin')) AS hour
FROM attack_log
WHERE attack_log.honeypot_id = $1
  AND TO_TIMESTAMP(time_of_event) >= NOW() - INTERVAL '24 hours'
GROUP BY attack_log.country,
         EXTRACT(HOUR FROM (TO_TIMESTAMP(time_of_event) AT TIME ZONE 'UTC' AT TIME ZONE 'Europe/Berlin'))
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
				return err
			}
			defer rows.Close()
			// keyed by hour
			var tokens map[int][]types.CountryStats = make(map[int][]types.CountryStats)
			for rows.Next() {
				var country string
				var count int
				var hour int
				err := rows.Scan(&country, &count, &hour)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.CountryStats{
					Country: country,
					Count:   count,
				}
				if _, ok := tokens[hour]; !ok {
					tokens[hour] = []types.CountryStats{res}
				} else {
					tokens[hour] = append(tokens[hour], res)
				}
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

// GetAttacksIn24Hours returns attack events in 24hours from DB
func (p *PostgreSQL) GetLatestAttacks() types.SetResponse {
	var idRes types.SetResponse = make(map[string][]types.Set)

	honeypotIDs := p.honeypotIds()

	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
				SELECT * FROM attack_log 
				WHERE attack_log.honeypot_id=$1
				ORDER BY time_of_event DESC
				LIMIT 20;`
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
				return err
			}
			defer rows.Close()

			var tokens []types.Set
			for rows.Next() {
				var ip_address, country, attack_id, attack_type, honeypot_id string
				var time_of_event int
				var port_nr int
				err := rows.Scan(&attack_id, &honeypot_id, &time_of_event, &port_nr, &ip_address, &country, &attack_type)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.Set{
					SUB:     ip_address,
					COUNTRY: country,
					ISS:     "github.com/l3montree-dev/oh-my-honeypot/honeypot/",
					IAT:     int64(time_of_event),
					JTI:     attack_id,
					Events:  make(map[string]map[string]interface{}),
				}
				if attack_type == "Login Attempt" {
					res.Events[honeypot.LoginEventID] = map[string]interface{}{
						"port": port_nr,
					}
				} else if attack_type == "HTTP Request" {
					res.Events[honeypot.HTTPEventID] = map[string]interface{}{
						"port": port_nr,
					}
				} else if attack_type == "Port Scanning" {
					res.Events[honeypot.PortEventID] = map[string]interface{}{
						"port": port_nr,
					}
				}

				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting attacks in 24 hours", "err", err)
	}

	return idRes
}

// GetCountIn24Hours returns number of attacks per day for last 7 days from DB
func (p *PostgreSQL) GetCountIn24Hours() types.CountIn24HoursStatsResponse {
	var idRes types.CountIn24HoursStatsResponse = make(map[string][]types.CountIn24HoursStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
			SELECT COUNT(attack_log.country),
       EXTRACT(HOUR FROM (TO_TIMESTAMP(time_of_event) AT TIME ZONE 'UTC' AT TIME ZONE 'Europe/Berlin')) AS hour
FROM attack_log
WHERE attack_log.honeypot_id = $1
  AND TO_TIMESTAMP(time_of_event) >= NOW() - INTERVAL '24 hours'
GROUP BY EXTRACT(HOUR FROM (TO_TIMESTAMP(time_of_event) AT TIME ZONE 'UTC' AT TIME ZONE 'Europe/Berlin'))

    	`
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
				return err
			}
			defer rows.Close()
			var tokens []types.CountIn24HoursStats
			for rows.Next() {
				var hour int
				var count int
				err := rows.Scan(&count, &hour)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
					return err
				}
				res := types.CountIn24HoursStats{
					Hour:  hour,
					Count: count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) GetCountIn7Days() types.CountIn7DaysStatsResponse {
	var idRes types.CountIn7DaysStatsResponse = make(map[string][]types.CountIn7DaysStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT TO_CHAR(TO_TIMESTAMP(time_of_event), 'DD/MM') AS date,
		COUNT(*) AS count
		FROM attack_log
		WHERE TO_TIMESTAMP(time_of_event) >= CURRENT_DATE - INTERVAL '7 days'
		AND attack_log.honeypot_id=$1
		GROUP BY TO_CHAR(TO_TIMESTAMP(time_of_event), 'DD/MM')
		ORDER BY date;
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
			}
			defer rows.Close()
			var tokens []types.CountIn7DaysStats
			for rows.Next() {
				var date string
				var count int
				err := rows.Scan(&date, &count)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.CountIn7DaysStats{
					Date:  date,
					Count: count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) GetCountIn6Months() types.CountIn6MonthsStatsResponse {
	var idRes types.CountIn6MonthsStatsResponse = make(map[string][]types.CountIn6MonthsStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT TO_CHAR(TO_TIMESTAMP(time_of_event), 'MM/YYYY') AS month,
		COUNT(*) AS count
		FROM attack_log
		WHERE TO_TIMESTAMP(time_of_event) >= CURRENT_DATE - INTERVAL '6 months'
		AND attack_log.honeypot_id=$1
		GROUP BY TO_CHAR(TO_TIMESTAMP(time_of_event), 'MM/YYYY')
		ORDER BY month;
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
			}
			defer rows.Close()
			var tokens []types.CountIn6MonthsStats
			for rows.Next() {
				var month string
				var count int
				err := rows.Scan(&month, &count)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.CountIn6MonthsStats{
					Month: month,
					Count: count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) GetCountryStats() types.CountryStatsResponse {
	var idRes types.CountryStatsResponse = make(map[string][]types.CountryStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
        SELECT attack_log.country, COUNT(attack_log.country) AS count
        FROM attack_log
        WHERE attack_log.honeypot_id=$1
        GROUP BY attack_log.country
        ORDER BY COUNT(attack_log.country) DESC
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
			}
			defer rows.Close()
			var tokens []types.CountryStats
			for rows.Next() {
				var country string
				var count int
				err := rows.Scan(&country, &count)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.CountryStats{
					Country: country,
					Count:   count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) GetIPStats() types.IPStatsResponse {
	var idRes types.IPStatsResponse = make(map[string][]types.IPStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT attack_log.ip_address, attack_log.country, COUNT(attack_log.ip_address) AS count
		FROM attack_log
		WHERE attack_log.honeypot_id=$1
		GROUP BY attack_log.ip_address, attack_log.country
		ORDER BY COUNT(attack_log.ip_address) 
		DESC;
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
			}
			defer rows.Close()
			var tokens []types.IPStats
			for rows.Next() {
				var ip_address, country string
				var count int
				err := rows.Scan(&ip_address, &country, &count)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.IPStats{
					IP:      ip_address,
					Country: country,
					Count:   count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) GetUsernameStats() types.UsernameStatsResponse {
	var idRes types.UsernameStatsResponse = make(map[string][]types.UsernameStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT la.username, COUNT(la.username) AS count
		FROM login_attempt la
		JOIN attack_log al ON la.attack_id = al.attack_id
		WHERE al.honeypot_id = $1
		GROUP BY la.username
		ORDER BY COUNT(la.username) DESC;
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
			}
			defer rows.Close()
			var tokens []types.UsernameStats
			for rows.Next() {
				var username string
				var count int
				err := rows.Scan(&username, &count)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.UsernameStats{
					Username: username,
					Count:    count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) GetPasswordStats() types.PasswordStatsResponse {
	var idRes types.PasswordStatsResponse = make(map[string][]types.PasswordStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT la.password, COUNT(la.password) AS count
		FROM login_attempt la
		JOIN attack_log al ON la.attack_id = al.attack_id
		WHERE al.honeypot_id = $1
		GROUP BY la.password
		ORDER BY COUNT(la.password) DESC;
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
			}
			defer rows.Close()
			var tokens []types.PasswordStats
			for rows.Next() {
				var password string
				var count int
				err := rows.Scan(&password, &count)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.PasswordStats{
					Password: password,
					Count:    count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) GetPortStats() types.PortStatsResponse {
	var idRes types.PortStatsResponse = make(map[string][]types.PortStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT attack_log.port_nr, COUNT(attack_log.port_nr) AS count
		FROM attack_log
		WHERE attack_log.honeypot_id=$1
		GROUP BY attack_log.port_nr
		ORDER BY COUNT(attack_log.port_nr) 
		DESC ;
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
			}
			defer rows.Close()
			var tokens []types.PortStats
			for rows.Next() {
				var count, port_nr int
				err := rows.Scan(&port_nr, &count)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.PortStats{
					Port:  port_nr,
					Count: count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) GetPathStats() types.PathStatsResponse {
	var idRes types.PathStatsResponse = make(map[string][]types.PathStats)
	honeypotIDs := p.honeypotIds()
	wg := errgroup.Group{}
	wg.SetLimit(10)
	mut := sync.Mutex{}
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT la.path, COUNT(la.path) AS count
		FROM http_request la
		JOIN attack_log al ON la.attack_id = al.attack_id
		WHERE al.honeypot_id=$1
		GROUP BY la.path
		ORDER BY COUNT(la.path)
		DESC ;
    `
			rows, err := p.DB.Query(query, honeypotID)
			if err != nil {
				slog.Error("Error querying the database", "err", err)
			}
			defer rows.Close()
			var tokens []types.PathStats
			for rows.Next() {
				var path string
				var count int
				err := rows.Scan(&path, &count)
				if err != nil {
					slog.Error("Error scanning the database", "err", err)
				}
				res := types.PathStats{
					Path:  path,
					Count: count,
				}
				tokens = append(tokens, res)
			}
			mut.Lock()
			idRes[honeypotID] = tokens
			mut.Unlock()
			return nil
		})
	}
	err := wg.Wait()
	if err != nil {
		slog.Error("Error getting count in 24 hours", "err", err)
	}
	return idRes
}

func (p *PostgreSQL) honeypotIds() []string {
	if len(p.honeypotIDs) == 0 {
		var err error
		p.honeypotIDs, err = p.getHoneypotIDs()
		if err != nil {
			slog.Error("Error getting honeypot ids", "err", err)
		}
	}
	return p.honeypotIDs
}

func (p *PostgreSQL) getHoneypotIDs() ([]string, error) {
	rows, err := p.DB.Query(`
		SELECT DISTINCT honeypot_id
		FROM attack_log;
	`)
	if err != nil {
		slog.Error("Error querying the database", "err", err)
		return nil, err
	}
	defer rows.Close()
	var Honeypot_IDs []string
	for rows.Next() {
		var honeypot_id string
		err := rows.Scan(&honeypot_id)
		if err != nil {
			slog.Error("Error scanning the database", "err", err)
			continue
		}
		Honeypot_IDs = append(Honeypot_IDs, honeypot_id)
	}
	if err := rows.Err(); err != nil {
		slog.Error("Error scanning the database", "err", err)
		return nil, err
	}
	return Honeypot_IDs, nil

}
