package utils

import "net"

func NetAddrToIpStr(addr net.Addr) (string, error) {
	ip, _, err := net.SplitHostPort(addr.String())

	if err != nil {
		return "", err
	}

	return ip, nil
}
