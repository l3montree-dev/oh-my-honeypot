package types

// key is honeypot id

type CountIn24HoursStatsResponse = map[string][]CountIn24HoursStats
type CountIn24HoursStats struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

type CountIn24HoursByCountry = map[int][]CountryStats

type CountIn24HoursByCountryResponse = map[string]CountIn24HoursByCountry

type CountIn7DaysStatsResponse = map[string][]CountIn7DaysStats
type CountIn7DaysStats struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type CountIn6MonthsStatsResponse = map[string][]CountIn6MonthsStats
type CountIn6MonthsStats struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}

type IPStatsResponse = map[string][]IPStats
type IPStats struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Count   int    `json:"count"`
}

type CountryStatsResponse = map[string][]CountryStats
type CountryStats struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

type UsernameStatsResponse = map[string][]UsernameStats
type UsernameStats struct {
	Username string `json:"username"`
	Count    int    `json:"count"`
}

type PasswordStatsResponse = map[string][]PasswordStats
type PasswordStats struct {
	Password string `json:"password"`
	Count    int    `json:"count"`
}

type PathStatsResponse = map[string][]PathStats
type PathStats struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

type PortStatsResponse = map[string][]PortStats
type PortStats struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}
