package set

import "encoding/json"

// Security Event Token
// Proposed by the IETF in RFC 8417
type Token struct {
	// Subject
	// always an ip address
	SUB string `json:"sub"`
	ISS string `json:"iss"`
	// The time at which the event occurred.
	IAT int64 `json:"iat"`
	// id of the set
	JTI string `json:"jti"`
	// Audience
	AUD *[]string `json:"aud,omitempty"`
	// Time of event
	TOE int64 `json:"toe"`
	// events - the key has to be a uri
	Events map[string]map[string]interface{} `json:"events"`
}

func Marshal(t Token) ([]byte, error) {
	return json.Marshal(t)
}
