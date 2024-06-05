package types

type CountIn24HoursStats struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}
type CountIn7DaysStats struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}
type CountIn6MonthsStats struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}
type IPStats struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Count   int    `json:"count"`
}
type CountryStats struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}
type UsernameStats struct {
	Username string `json:"username"`
	Count    int    `json:"count"`
}
type PasswordStats struct {
	Password string `json:"password"`
	Count    int    `json:"count"`
}
type PathStats struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}
type PortStats struct {
	Port  string `json:"port"`
	Count int    `json:"count"`
}
