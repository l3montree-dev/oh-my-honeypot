package dbip_test

import (
	"net"
	"testing"

	"github.com/l3montree-dev/oh-my-honeypot/packages/dbip"
)

func TestLookup1(t *testing.T) {
	dbIp := dbip.NewIpToCountry("../../dbip-country.csv")

	ip := net.ParseIP("1.1.0.0")
	country := dbIp.Lookup(ip)
	if country != "CN" {
		t.Errorf("Expected CN, got %s", country)
	}
}

func TestCompare(t *testing.T) {
	// 60.213.192.0,60.223.255.255,CN
	r := dbip.IPRange{Start: dbip.IP2int(net.ParseIP("60.213.192.0")), End: dbip.IP2int(net.ParseIP("60.223.255.255")), Country: "CN"}

	actual := r.Compare(dbip.IPRange{Start: dbip.IP2int(net.ParseIP("60.221.224.113")), End: dbip.IP2int(net.ParseIP("60.221.224.113"))})

	if actual != 0 {
		t.Errorf("Expected 0, got %d", actual)
	}
}
func TestLookup2(t *testing.T) {
	dbIp := dbip.NewIpToCountry("../../dbip-country.csv")

	ip := net.ParseIP("60.221.224.113")
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
