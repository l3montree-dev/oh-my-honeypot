package types

import (
	"encoding/json"
	"net"
	"time"
)

// Security Event Token
// Proposed by the IETF in RFC 8417
type Set struct {
	// Subject
	// always an ip address
	SUB      string `json:"sub"`
	COUNTRY  string `json:"subCountry"`
	ISS      string `json:"iss"`
	HONEYPOT string `json:"issHoneypot"`
	// The time at which the event occurred.
	IAT int64 `json:"iat"`
	// id of the set
	JTI string `json:"jti"`
	// Audience
	AUD *[]string `json:"aud,omitempty"`
	// events - the key has to be a uri
	Events map[string]map[string]interface{} `json:"events"`
}

// key is honeypot id
type SetResponse = map[string][]Set

func Marshal(t Set) ([]byte, error) {
	return json.Marshal(t)
}

func (t Set) GetIssuedAt() time.Time {
	return time.Unix(t.IAT, 0)
}

func ParseSubToIp(sub string) (net.IP, error) {
	ip, _, err := net.SplitHostPort(sub)

	if err != nil {
		return nil, err
	}

	return net.ParseIP(ip), nil
}
