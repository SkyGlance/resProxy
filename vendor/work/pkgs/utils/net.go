package utils

import (
	"net"
	"strconv"
	"strings"
)

func IsLocalIP(IP net.IP) bool {
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return true
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		default:
			return false
		}
	}
	return true
}

func IsIPAddress(host string) bool {
	pindex := strings.Index(host, ":")
	if pindex > 0 {
		host = host[:pindex]
	}
	strvec := strings.Split(host, ".")
	if len(strvec) != 4 {
		return false
	}
	for _, str := range strvec {
		if len(str) > 3 || len(str) <= 0 {
			return false
		}
		for _, b := range str {
			if !(b >= '0' && b <= '9') {
				return false
			}
		}
		num, _ := strconv.Atoi(str)
		if num >= 256 || num < 0 {
			return false
		}
	}
	return true
}
