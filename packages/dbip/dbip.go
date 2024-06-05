package dbip

import (
	"encoding/csv"
	"log/slog"
	"math/big"
	"net"
	"os"

	"github.com/l3montree-dev/oh-my-honeypot/packages/utils"
)

func IP2int(ip net.IP) int64 {
	i := big.NewInt(0)
	if ip.To4() == nil {
		// ipv6
		i.SetBytes(ip.To16())
		return i.Int64()
	}
	i.SetBytes(ip.To4())

	return i.Int64()
}

type IPRange struct {
	Start   int64
	End     int64
	Country string
}

func (e IPRange) Compare(other IPRange) int {
	if other.Start >= e.Start && other.End <= e.End {
		// either this Entry is inside the other Entry or the other Entry is inside this Entry
		return 0
	}
	return int(e.Start - other.Start)
}

type IpToCountry struct {
	dataset []IPRange
}

func (i *IpToCountry) Lookup(ip net.IP) string {
	// convert ip to uint32
	// binary search the dataset for the Entry
	intRep := IP2int(ip)
	/*for _, Entry := range i.dataset {
		if intRep >= Entry.start && intRep <= Entry.end {
			log.Println(i)
			return Entry.country
		}
	}*/

	index := utils.BinarySearch(i.dataset, IPRange{Start: intRep, End: intRep})
	if index != -1 {
		return i.dataset[index].Country
	}
	return "UNKNOWN"
}

func readDBIPCountryFile(filename string) []IPRange {
	csvFile, err := os.Open(filename)
	if err != nil {
		slog.Error("Error opening file", "error", err)
	}
	defer csvFile.Close()
	result := make([]IPRange, 0)
	reader := csv.NewReader(csvFile)
	for {
		line, err := reader.Read()
		if err != nil {
			break
		}
		start := net.ParseIP(line[0])
		if start == nil || start.To4() == nil {
			continue
		}
		result = append(result, IPRange{
			Start:   IP2int(net.ParseIP(line[0])),
			End:     IP2int(net.ParseIP(line[1])),
			Country: line[2],
		})
	}
	return result
}

func NewIpToCountry(filename string) *IpToCountry {
	// read the dbip country csv
	// create a slice of entries
	// sort the slice by start ip
	// return the IpToCountry struct
	return &IpToCountry{
		dataset: readDBIPCountryFile(filename),
	}
}
