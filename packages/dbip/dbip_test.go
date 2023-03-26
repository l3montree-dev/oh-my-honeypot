package dbip_test

import (
	"net"
	"testing"

	"gitlab.com/neuland-homeland/honeypot/packages/dbip"
)

func TestLookup(t *testing.T) {
	dbIp := dbip.NewIpToCountry("../../dbip-country.csv")
	ip := net.ParseIP("1.1.0.0")
	country := dbIp.Lookup(ip)
	if country != "CN" {
		t.Errorf("Expected CN, got %s", country)
	}
}

func TestIP2Int(t *testing.T) {
	ip := net.ParseIP("64.233.187.99")
	print(ip)
	intRep := dbip.IP2int(ip)
	if intRep != 1089059683 {
		t.Errorf("Expected 1089059683, got %d", intRep)
	}
}
