package dns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsMsgData struct {
	last time.Time
	ips  []string
}

var (
	hmlk        sync.Mutex
	hmap        map[string]*dnsMsgData
	nameservers []string
	expireTime  time.Duration
)

//LookupIP get host ipaddress
func LookupIP(address string) ([]net.IP, error) {
	var ipvec []net.IP
	ips := GetHostsByName(address)
	if len(ips) <= 0 {
		return ipvec, fmt.Errorf("host:%s not found", address)
	}
	for _, s := range ips {
		p := net.ParseIP(s)
		ipvec = append(ipvec, p)
	}
	return ipvec, nil
}

//GetHostsByName get domain ips
func GetHostsByName(domain string) (ips []string) {
	domain = strings.ToLower(domain)
	p := net.ParseIP(domain)
	if p != nil {
		ips = append(ips, domain)
		return
	}
	if len(nameservers) <= 0 {
		log.Printf("Warning Name servers empty\n")
		return
	}

	hmlk.Lock()
	res, ok := hmap[domain]
	if ok {
		if time.Since(res.last) <= expireTime {
			hmlk.Unlock()
			ips = make([]string, len(res.ips))
			copy(ips, res.ips)
			return
		}
	}
	hmlk.Unlock()

	ms := new(dns.Msg)
	ms.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	c := new(dns.Client)
	nmd := new(dnsMsgData)
	nmd.last = time.Now()
	for _, ns := range nameservers {
		msg, _, err := c.Exchange(ms, ns)
		if err != nil {
			log.Printf("Parse domain:%s ns:%s failed:%s\n", domain, ns, err)
			continue
		}
		if !msg.Response {
			log.Printf("Parse domain:%s ns:%s res empty\n", domain, ns)
			continue
		}
		for _, v := range msg.Answer {
			switch ansb := v.(type) {
			case *dns.A:
				nmd.ips = append(nmd.ips, ansb.A.String())
			}
		}
		break
	}

	if len(nmd.ips) > 0 {
		ips = make([]string, len(nmd.ips))
		copy(ips, nmd.ips)
		hmlk.Lock()
		hmap[domain] = nmd
		hmlk.Unlock()
	} else if res != nil {
		ips = make([]string, len(res.ips))
		copy(ips, res.ips)
		log.Printf("Domain:%s refresh ips failed\n", domain)
	}
	return
}

//SetDNSDomains set dns
func SetDNSDomains(saddrs []string, timeout time.Duration) {
	hmlk.Lock()
	hmap = make(map[string]*dnsMsgData)
	nameservers = make([]string, len(saddrs))
	copy(nameservers, saddrs)
	if timeout <= time.Second {
		expireTime = 60 * time.Second
	} else {
		expireTime = timeout
	}
	hmlk.Unlock()
}
