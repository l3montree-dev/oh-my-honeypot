package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/oh-my-honeypot/packages/honeypot"
	"github.com/l3montree-dev/oh-my-honeypot/packages/types"
	_ "github.com/lib/pq"
	"golang.org/x/sync/errgroup"
)

type PostgreSQL struct {
	DB          *pgxpool.Pool
	honeypotIDs []string
}

type attackNotification struct {
	AttackID    string `json:"attack_id"`
	HoneypotID  string `json:"honeypot_id"`
	TimeOfEvent int    `json:"time_of_event"`
	PortNr      int    `json:"port_nr"`
	IPAddress   string `json:"ip_address"`
	Country     string `json:"country"`
	AttackType  string `json:"attack_type"`
}

var attackTypeToID = map[string]string{
	"Login Attempt": honeypot.LoginEventID,
	"HTTP Request":  honeypot.HTTPEventID,
	"Port Scanning": honeypot.PortEventID,
}

// uses postgresql listener to listen to the database
func (p *PostgreSQL) SubscribeToDBChanges() <-chan types.Set {
	_, err := p.DB.Exec(context.Background(), `CREATE OR REPLACE FUNCTION fn_attack() RETURNS TRIGGER AS 
$$
BEGIN
    PERFORM pg_notify(
        'honeypot',
        to_json(NEW)::TEXT
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER new_attacks
AFTER INSERT ON attack_log
FOR EACH ROW EXECUTE PROCEDURE fn_attack();`)
	if err != nil {
		slog.Error("Error creating the trigger", "err", err)
		panic(err)
	}

	conn, err := p.DB.Acquire(context.Background())
	if err != nil {
		slog.Error("Error acquiring the connection", "err", err)
		panic(err)
	}

	_, err = conn.Exec(context.Background(), "LISTEN honeypot")

	if err != nil {
		slog.Error("Error listening to the database", "err", err)
		panic(err)
	}

	output := make(chan types.Set)
	go func() {
		for {
			notification, err := conn.Conn().WaitForNotification(context.Background())
			if err != nil {
				slog.Error("Error waiting for notification", "err", err)
				continue
			}
			var attack attackNotification

			err = json.Unmarshal([]byte(notification.Payload), &attack)
			if err != nil {
				slog.Error("Error unmarshalling the notification", "err", err)
				continue
			}

			select {
			case output <- types.Set{
				SUB:     attack.IPAddress,
				COUNTRY: attack.Country,
				ISS:     "github.com/l3montree-dev/oh-my-honeypot/honeypot/",
				IAT:     int64(attack.TimeOfEvent),
				JTI:     attack.AttackID,
				Events: map[string]map[string]any{
					attackTypeToID[attack.AttackType]: {
						"port": attack.PortNr,
					}},
				HONEYPOT: attack.HoneypotID,
			}:
			default:
				slog.Warn("Could not send the notification")
			}
		}
	}()

	return output
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
					referrer := httpEvent["referrer"].(string)
					//store the payload if the method is POST, PUT or PATCH
					if method == "POST" || method == "PUT" || method == "PATCH" {
						payload := httpEvent["body"].(string)
						if httpEvent["username"] != "" && httpEvent["password"] != "" {
							username := httpEvent["username"].(string)
							password := httpEvent["password"].(string)
							bot := httpEvent["bot"].(string)
							defer p.injectionInsert(input.JTI, username, password, bot)
						} else {
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
					}
					if httpEvent["attack-type"] == "credential-theft" {
						randomPW := httpEvent["randomPW"].(string)
						defer p.pwsInsert(input.JTI, randomPW)
					}
					defer p.httpInsert(input.JTI, method, path, acceptLanguage, useragent, referrer)
				}
				// Insert the basic information about all attacks into the database
				p.attackInsert(input.JTI, input.HONEYPOT, int(timestamp), port, input.SUB, input.COUNTRY, attackType)
			}()
		}
	}()
	return res
}

func (p *PostgreSQL) DeleteEverythingBefore(date time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	_, err := p.DB.Exec(ctx, `
	DELETE FROM attack_log
	WHERE TO_TIMESTAMP(time_of_event) < $1
	`, date)
	if err != nil {
		slog.Error("Error deleting from the database", "err", err)
	}
}

// Insert the attack into the database and sanitize the input by using prepared statements
func (p *PostgreSQL) attackInsert(attackID string, honeypot_id string, t int, port int, ip string, country string, attackType string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := p.DB.Exec(ctx, `
	INSERT INTO attack_log (Attack_id,Honeypot_id, Time_Of_Event,Port_Nr,IP_Address,Country,Attack_Type)
	VALUES ($1, $2, $3, $4,$5, $6, $7);
	`, attackID, honeypot_id, t, port, ip, country, attackType)
	if err != nil {
		slog.Error("Error inserting into the database attack_log", "err", err)
	}
}

func (p *PostgreSQL) loginAttemptInsert(attackID string, service string, username string, password string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.DB.Exec(ctx, `
	INSERT INTO login_attempt (Attack_ID,service,Username,Password)
	VALUES ($1, $2, $3,$4)
	`, attackID, service, username, password)
	if err != nil {
		slog.Error("Error inserting into the database login_attempt", "err", err)
	}
}

func (p *PostgreSQL) httpInsert(attackID string, method string, path string, acceptLanguage string, useragent []string, referrer string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.DB.Exec(ctx, `
	INSERT INTO http_request (Attack_ID,method,path,accept_language,system,rendering_engine,platform,referrer)
	VALUES ($1, $2, $3, $4, $5, $6,$7,$8)
	`, attackID, method, path, acceptLanguage, useragent[0], useragent[1], useragent[2], referrer)
	if err != nil {
		slog.Error("Error inserting into the database http_request", "err", err)
	}
}

func (p *PostgreSQL) bodyInsert(attackID string, contentType string, payloadSize string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.DB.Exec(ctx, `
	INSERT INTO http_body (Attack_ID,content_type,payload_size)
	VALUES ($1,$2,$3)
	`, attackID, contentType, payloadSize)
	if err != nil {
		slog.Error("Error inserting into the database http_body", "err", err)
	}
}

func (p *PostgreSQL) injectionInsert(attackID string, username string, password string, bot string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.DB.Exec(ctx, `
	INSERT INTO http_injection (Attack_ID,username,password,bot)
	VALUES ($1,$2,$3,$4)
	`, attackID, username, password, bot)
	if err != nil {
		slog.Error("Error inserting into the database http_injection", "err", err)
	}
}
func (p *PostgreSQL) pwsInsert(attackID string, password string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.DB.Exec(ctx, `
	INSERT INTO generated_pws (Attack_ID,password)
	VALUES ($1,$2)
	`, attackID, password)
	if err != nil {
		slog.Error("Error inserting into the database http_injection", "err", err)
	}
}

type tracer struct {
}

func (t tracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	newCtx := context.WithValue(ctx, "start", time.Now()) // nolint
	return context.WithValue(newCtx, "query", data.SQL)   // nolint
}

func (t tracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	// if the query takes more than 200ms, log it
	if time.Since(ctx.Value("start").(time.Time)) > 200*time.Millisecond {
		slog.Warn("Slow query", "query", time.Since(ctx.Value("start").(time.Time)), "err", data.Err)
		fmt.Println(ctx.Value("query"))
	}
}

// Start initializes the PostgreSQL database connection.
func (p *PostgreSQL) Start(host, port, user, password, dbname string) error {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	dbConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		slog.Error("Failed to create a config", "err", err)
		return err
	}

	dbConfig.MaxConns = int32(10)
	dbConfig.MinConns = int32(0)
	dbConfig.MaxConnLifetime = time.Hour
	dbConfig.MaxConnIdleTime = time.Minute * 30
	dbConfig.HealthCheckPeriod = time.Minute
	dbConfig.ConnConfig.ConnectTimeout = time.Second * 5

	dbConfig.ConnConfig.Tracer = &tracer{}

	connPool, err := pgxpool.NewWithConfig(context.Background(), dbConfig)

	if err != nil {
		slog.Error("Error opening the database connection", "err", err)
		return err
	}
	// Set the database connection in the postgreSQL struct
	p.DB = connPool
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	//Create the tables if they do not exist
	_, err = connPool.Exec(ctx, `
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
	_, err = p.DB.Exec(ctx, `
	CREATE TABLE IF NOT EXISTS login_attempt (
		Attack_ID TEXT PRIMARY KEY, 
		Service TEXT, Username TEXT, 
		Password TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID) ON DELETE CASCADE
		);`)
	if err != nil {
		slog.Error("Error creating table login_attempt", "err", err)
	}
	_, err = p.DB.Exec(ctx, `
	CREATE TABLE IF NOT EXISTS http_request (
		Attack_ID TEXT PRIMARY KEY, 
		method TEXT, 
		path TEXT, 
		accept_language TEXT, 
		system TEXT, 
		rendering_engine TEXT, 
		platform TEXT, 
		referrer TEXT,
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID) ON DELETE CASCADE
		);`)
	if err != nil {
		slog.Error("Error creating table http_request", "err", err)
	}
	_, err = p.DB.Exec(ctx, `
	CREATE TABLE IF NOT EXISTS http_body (
		Attack_ID TEXT PRIMARY KEY, 
		content_type TEXT, 
		payload_size TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID) ON DELETE CASCADE);`)
	if err != nil {
		slog.Error("Error creating table http_body", "err", err)
	}
	_, err = p.DB.Exec(ctx, `
	CREATE TABLE IF NOT EXISTS http_injection (
		Attack_ID TEXT PRIMARY KEY, 
		username TEXT, 
		password TEXT, 
		bot TEXT,
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID) ON DELETE CASCADE);`)
	if err != nil {
		slog.Error("Error creating table http_injection", "err", err)
	}
	_, err = p.DB.Exec(ctx, `
	CREATE TABLE IF NOT EXISTS generated_pws (
		Attack_ID TEXT PRIMARY KEY, 
		password TEXT, 
		FOREIGN KEY (Attack_ID) REFERENCES attack_log(Attack_ID) ON DELETE CASCADE);`)
	if err != nil {
		slog.Error("Error creating table http_injection", "err", err)
	}
	_, err = p.DB.Exec(ctx, `
	CREATE INDEX  IF NOT EXISTS attacklog_timestamp_hpid
	ON attack_log(honeypot_id, TO_TIMESTAMP(time_of_event));`)
	if err != nil {
		slog.Error("Error creating index", "err", err)
	}

	slog.Info("PostgreSQL store started")

	honeypotIds := p.honeypotIds()
	slog.Info("Honeypot IDs", "ids", honeypotIds)
	return nil
}

// Close closes the PostgreSQL database connection.
func (p *PostgreSQL) Close() error {
	// Close the database connection
	if p.DB != nil {
		p.DB.Close()
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
				SELECT * FROM attack_log 
				WHERE attack_log.honeypot_id=$1
				ORDER BY time_of_event DESC
				LIMIT 20;`
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
					SUB:      ip_address,
					COUNTRY:  country,
					ISS:      "github.com/l3montree-dev/oh-my-honeypot/honeypot/",
					IAT:      int64(time_of_event),
					JTI:      attack_id,
					HONEYPOT: honeypot_id,
					Events:   make(map[string]map[string]interface{}),
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
        SELECT attack_log.country, COUNT(attack_log.country) AS count
        FROM attack_log
        WHERE attack_log.honeypot_id=$1
        GROUP BY attack_log.country
        ORDER BY COUNT(attack_log.country) DESC
    `
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT attack_log.ip_address, attack_log.country, COUNT(attack_log.ip_address) AS count
		FROM attack_log
		WHERE attack_log.honeypot_id=$1
		GROUP BY attack_log.ip_address, attack_log.country
		ORDER BY COUNT(attack_log.ip_address) 
		DESC LIMIT 30;
    `
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT la.username, COUNT(la.username) AS count
		FROM login_attempt la
		JOIN attack_log al ON la.attack_id = al.attack_id
		WHERE al.honeypot_id = $1
		GROUP BY la.username
		ORDER BY COUNT(la.username) DESC LIMIT 30;
    `
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT la.password, COUNT(la.password) AS count
		FROM login_attempt la
		JOIN attack_log al ON la.attack_id = al.attack_id
		WHERE al.honeypot_id = $1
		GROUP BY la.password
		ORDER BY COUNT(la.password) DESC LIMIT 30;
    `
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, honeypotID := range honeypotIDs {
		wg.Go(func() error {
			query := `
		SELECT la.path, COUNT(la.path) AS count
		FROM http_request la
		JOIN attack_log al ON la.attack_id = al.attack_id
		WHERE al.honeypot_id=$1
		GROUP BY la.path
		ORDER BY COUNT(la.path)
		DESC
		LIMIT 10;
    `
			rows, err := p.DB.Query(ctx, query, honeypotID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := p.DB.Query(
		ctx,
		`
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
