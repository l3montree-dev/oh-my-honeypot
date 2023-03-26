package dbip

import (
	"encoding/csv"
	"math/big"
	"net"
	"os"

	"gitlab.com/neuland-homeland/honeypot/packages/utils"
)

func ip2int(ip net.IP) int64 {

	i := big.NewInt(0)
	i.SetBytes(ip)
	return i.Int64()
}

type entry struct {
	start   int64
	end     int64
	country string
}

func (e entry) Compare(other entry) int {
	if e.start >= other.start && e.start <= other.end || e.end >= other.start && e.end <= other.end {
		// either this entry is inside the other entry or the other entry is inside this entry
		return 0
	}
	return int(e.start - other.start)
}

type IpToCountry struct {
	dataset []entry
}

func (i *IpToCountry) Lookup(ip net.IP) string {
	// convert ip to uint32
	// binary search the dataset for the entry
	intRep := ip2int(ip)
	index := utils.BinarySearch(i.dataset, entry{start: intRep, end: intRep})
	if index != -1 {
		return i.dataset[index].country
	}
	return "UNKNOWN"
}

func readDBIPCountryFile() []entry {
	csvFile, err := os.Open("dbip-country.csv")
	if err != nil {
		panic(err)
	}
	defer csvFile.Close()
	result := make([]entry, 0)
	reader := csv.NewReader(csvFile)
	for {
		line, err := reader.Read()
		if err != nil {
			break
		}
		result = append(result, entry{
			start:   ip2int(net.ParseIP(line[0])),
			end:     ip2int(net.ParseIP(line[1])),
			country: line[2],
		})
	}
	return result
}

func NewIpToCountry() *IpToCountry {
	// read the dbip country csv
	// create a slice of entries
	// sort the slice by start ip
	// return the IpToCountry struct
	return &IpToCountry{
		dataset: readDBIPCountryFile(),
	}
}
