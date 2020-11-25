package resProxy

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"work/pkgs/base62"
	"work/pkgs/goproxy"
	"work/pkgs/uuid"

	"github.com/gorilla/websocket"
	json "github.com/json-iterator/go"
)

const (
	webMsgChanSize = 10
	tunVersion     = "v1.2.0"
)

// CallLogInterface log interface
type CallLogInterface interface {
	OnError(code string, reason string)
	OnLog(code string, reason string)
}

type clientProxy struct {
	vodSpeed    int64
	liveSpeed   int64
	webClient   *webConn
	msg         *webMsg
	tunLock     sync.Mutex
	authStr     string
	tunMsgChan  chan *webMsg
	tunServerIP string

	vodPort      int
	vodProxyAddr string
	vodPorxy     *goproxy.Proxy
	vodTunLis    net.Listener

	livePort      int
	liveProxyAddr string
	livePorxy     *goproxy.Proxy
	liveTunLis    net.Listener

	userName string
	passWD   string

	updateURLs []string
	callLog    CallLogInterface
}

var (
	dnsServers = []string{
		"8.8.8.8:53", "8.8.4.4:53",
		"114.114.114.114:53", "223.5.5.5:53",
		"208.67.222.222:53", "208.67.222.220:53",
		"1.1.1.1:53", "1.0.0.1:53",
	}

	httpClient *http.Client
	tlsConf    *tls.Config

	clientLock sync.Mutex
	pclient    *clientProxy
)

func init() {
	root := getDecRootCrt()
	//	fmt.Printf("%s\n", root)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(root))
	cliCrt, err := tls.X509KeyPair([]byte(getDecClientCert()), []byte(getDecClientKey()))
	if err != nil {
		fmt.Println("Loadx509keypair err:", err)
		return
	}
	tlsConf = &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{cliCrt},
		InsecureSkipVerify: false,
	}
	goproxy.SetDNSDomains(dnsServers, 0)

	httpClient = &http.Client{
		Transport: &http.Transport{
			DialTLS: func(netw, addr string) (net.Conn, error) {
				nport := "443"
				id := strings.Index(addr, ":")
				if id > 0 {
					nport = addr[id+1:]
					addr = addr[:id]
				}
				ips := goproxy.GetHostsByName(addr)
				if len(ips) <= 0 {
					return nil, fmt.Errorf("dns resolve host:%s failed", addr)
				}
				//	ips = []string{"127.0.0.1"}
				host := fmt.Sprintf("%s:%s", ips[rand.Int()%len(ips)], nport)
				c, err := net.DialTimeout(netw, host, time.Second*10)
				if err != nil {
					return nil, err
				}
				conf := &tls.Config{
					ServerName:         addr,
					RootCAs:            tlsConf.RootCAs,
					Certificates:       tlsConf.Certificates,
					InsecureSkipVerify: false,
				}
				tlsConn := tls.Client(c, conf)
				err = tlsConn.Handshake()
				if err != nil {
					c.Close()
					return nil, err
				}
				return tlsConn, nil
			},

			Dial: func(netw, addr string) (net.Conn, error) {
				nport := "80"
				id := strings.Index(addr, ":")
				if id > 0 {
					nport = addr[id+1:]
					addr = addr[:id]
				}
				ips := goproxy.GetHostsByName(addr)
				if len(ips) <= 0 {
					return nil, errors.New("dns resolve error")
				}
				//	ips = []string{"127.0.0.1"}
				addr = fmt.Sprintf("%s:%s", ips[rand.Int()%len(ips)], nport)
				c, err := net.DialTimeout(netw, addr, time.Second*10)
				if err != nil {
					return nil, err
				}
				return c, nil
			},
			ResponseHeaderTimeout: 20 * time.Second,
			Proxy: func(req *http.Request) (*url.URL, error) {
				//	return http.ProxyFromEnvironment(req)
				return nil, nil
			},
			IdleConnTimeout: 60 * time.Second,
			// TODO: Make this configurable later on? The default of 2 is too low.
			// goals: (1) new connections should not be opened and closed frequently, (2) we should not run out of sockets.
			// This doesn't seem to need much tuning. The number of connections open at a given time seems to be less than 500, even when sending hundreds of pushes per second.
			MaxIdleConnsPerHost: 5,
			TLSClientConfig:     tlsConf,
		},
	}
}
func (cp *clientProxy) runSpeedTestProc(wc *webConn, ptest *speedTestData) {
	defer func() {
		select {
		case <-wc.die:
			log.Printf("Speed test msg chan closed")
			return
		default:
			msg := webMsg{
				MsgType:    "SPEED-TEST-REPLY",
				CurrentTun: cp.tunServerIP,
				Version:    tunVersion,
				SpeedTest:  ptest,
			}
			wc.writeChan <- &msg
		}
	}()

	dnfn := func(url string, rpl *speedTestReply) {
		start := time.Now()
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Printf("Speed test invalid addrs:%s err:%s", url, err)
			return
		}
		hostip := req.Host
		id := strings.Index(hostip, ":")
		if id > 0 {
			hostip = hostip[:id]
		}
		rpl.ResolveIPS = goproxy.GetHostsByName(hostip)
		req.Header.Add("Connection", "close")
		if req.Body != nil {
			defer req.Body.Close()
		}
		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("Speed test addrs:%s err:%s", url, err)
			return
		}
		rpl.ConSecs = int(time.Since(start) / time.Second)
		defer res.Body.Close()
		if res.StatusCode != 200 && res.StatusCode != 206 {
			log.Printf("Speed test addrs:%s reply:%d failed", url, res.StatusCode)
			return
		}
		buf := make([]byte, 4096)
		check := time.Now()
		lastbytes := 0
		start = time.Now()
		for {
			n, err := res.Body.Read(buf)
			if err != nil {
				usetime := int(time.Since(start)/time.Second) + 1
				rpl.AvgSpeed = rpl.DownBytes / usetime
				break
			}
			rpl.DownBytes += n
			ustime := int(time.Since(check) * 10 / time.Second)
			if ustime >= 30 {
				speed := (rpl.DownBytes - lastbytes) * 10 / ustime
				if rpl.MaxSpeed < speed {
					rpl.MaxSpeed = speed
				}
				if rpl.MinSpeed == 0 {
					rpl.MinSpeed = speed
				}
				if rpl.MinSpeed > speed {
					rpl.MinSpeed = speed
				}
				lastbytes = rpl.DownBytes
				check = time.Now()
			}
			if time.Since(start) >= 60*time.Second {
				rpl.AvgSpeed = rpl.DownBytes / int(time.Since(start)/time.Second)
				break
			}
		}
	}

	for _, s1 := range ptest.Addrs {
		s2 := fmt.Sprintf("%s%s", s1, ptest.TestURL)
		start := time.Now()
		rpl := speedTestReply{
			Adrr: s1,
		}
		dnfn(s2, &rpl)
		rpl.UseTime = int(time.Since(start) / time.Second)
		ptest.Replys = append(ptest.Replys, rpl)
	}

}

func (cp *clientProxy) runWebSocketClient(surl, signKey string, callLog CallLogInterface) {

	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConf,
		HandshakeTimeout: 10 * time.Second,
		Proxy: func(req *http.Request) (*url.URL, error) {
			//	return http.ProxyFromEnvironment(req)
			return nil, nil
		},
		NetDial: func(netw, addr string) (net.Conn, error) {
			nport := "80"
			id := strings.Index(addr, ":")
			if id > 0 {
				nport = addr[id+1:]
				addr = addr[:id]
			}
			ips := goproxy.GetHostsByName(addr)
			if len(ips) <= 0 {
				return nil, errors.New("dns resolve error")
			}
			//	ips = []string{"127.0.0.1"}
			addr = fmt.Sprintf("%s:%s", ips[rand.Int()%len(ips)], nport)
			c, err := net.DialTimeout(netw, addr, time.Second*10)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
	clientLock.Lock()
	userName := cp.userName
	passWord := cp.passWD
	clientLock.Unlock()

	randKey := uuid.New().String()
	req := http.Header{}
	keySign := sha256.Sum256([]byte(signKey + randKey + userName + passWord))

	req.Add("Web-Socket-User", userName)
	req.Add("Web-Socket-Password", base64.StdEncoding.EncodeToString([]byte(passWord)))
	req.Add("Web-Socket-Sign", fmt.Sprintf("%x", keySign[:24]))
	req.Add("Web-Socket-Uuid", randKey)
	req.Add("Web-Socket-TunVersion", tunVersion)
	req.Add("User-Agent", "go-web-socket-client")

	conn, res, err := dialer.Dial(surl, req)
	if err != nil {
		log.Printf("%s", err)
		if res != nil {
			errstr := res.Header.Get("web-socket-err")
			if len(errstr) > 0 {
				callLog.OnError(errstr, "user auth failed")
			}
			switch res.StatusCode {
			case 401:
				log.Printf("user login error,name:%s passwd:%s", userName, passWord)
				cp.callLog.OnError("ERR_AUTH_USER", "user authentication error")
				time.Sleep(15 * time.Second)
			case 403:
				log.Printf("tun request error")
				time.Sleep(10 * time.Second)
			default:
			}
			time.Sleep(10 * time.Second)
			return
		}
		return
	}
	defer conn.Close()
	web := webConn{
		conn: conn,
	}
	clientLock.Lock()
	cp.webClient = &web
	clientLock.Unlock()

	defer func() {
		web.Close()
		clientLock.Lock()
		cp.webClient = nil
		clientLock.Unlock()
	}()

	web.startWebSocketCon(webMsgChanSize)
	timer := time.NewTicker(10 * time.Second)
	defer timer.Stop()
	lastLiveBytes := atomic.LoadInt64(&cp.livePorxy.DownloadBytes)
	lastVodBytes := atomic.LoadInt64(&cp.vodPorxy.DownloadBytes)
	for {
		select {
		case msg := <-cp.tunMsgChan:
			web.writeChan <- msg
			log.Printf("websocket client tun msg")
		case <-timer.C:
			var lastBytes, vodSpeed, liveSpeed int64
			curLiveBytes := atomic.LoadInt64(&cp.livePorxy.DownloadBytes)
			curVodBytes := atomic.LoadInt64(&cp.vodPorxy.DownloadBytes)
			if curLiveBytes > lastLiveBytes {
				lastBytes += atomic.LoadInt64(&cp.livePorxy.DownloadBytes)
				liveSpeed = atomic.LoadInt64(&cp.liveSpeed)
				curLiveBytes = lastLiveBytes
			}
			if curVodBytes > lastVodBytes {
				lastBytes += atomic.LoadInt64(&cp.vodPorxy.DownloadBytes)
				vodSpeed = atomic.LoadInt64(&cp.vodSpeed)
				curVodBytes = lastVodBytes
			}
			msg := webMsg{
				MsgType:       "CLI-HEART",
				CurrentTun:    cp.tunServerIP,
				Version:       tunVersion,
				DownloadBytes: uint64(lastBytes),
				DownloadSpeed: uint64(liveSpeed + vodSpeed),
				UploadBytes:   uint64(liveSpeed),
				UploadSpeed:   uint64(vodSpeed),
			}
			web.writeChan <- &msg
			log.Printf("websocket client heartbeat")
		case msg := <-web.readChan:
			log.Printf("Recv New  msg:%s upd:%d tun:%d",
				msg.MsgType, len(msg.UpdateURLs), len(msg.TunServers))
			switch msg.MsgType {
			case "UPDATE_SVR":
				clientLock.Lock()
				cp.updateURLs = make([]string, len(msg.UpdateURLs))
				copy(cp.updateURLs, msg.UpdateURLs)
				clientLock.Unlock()
			case "SPEED_TEST":
				if msg.SpeedTest != nil || len(msg.SpeedTest.Addrs) <= 0 {
					log.Printf("Server Ctrl speed test:%s", msg.SpeedTest.Addrs)
					go cp.runSpeedTestProc(&web, msg.SpeedTest)
				} else {
					log.Printf("Ignore etmp speed test msg")
				}
			default:
			}
		case <-web.die:
			log.Printf("websocket client socket closed")
			return
		}
	}
}

type servMsg struct {
	Status  int      `json:"status"`
	Servers []string `json:"servers"`
}

func (cp *clientProxy) getWebSocketServers(signKey, url string) (svr []string, err error) {
	clientLock.Lock()
	userName := cp.userName
	passWord := cp.passWD
	clientLock.Unlock()

	randKey := uuid.New().String()
	keySign := sha256.Sum256([]byte(signKey + randKey + userName + passWord))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	//	request.Header.Add("Connection", "keep-alive")
	if req.Body != nil {
		defer req.Body.Close()
	}
	req.Header.Add("Web-Socket-User", userName)
	req.Header.Add("Web-Socket-Password", base64.StdEncoding.EncodeToString([]byte(passWord)))
	req.Header.Add("Web-Socket-Sign", fmt.Sprintf("%x", keySign[:24]))
	req.Header.Add("Web-Socket-Uuid", randKey)

	res, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return
	}
	auth := res.Header["Web-Socket-Auth"]
	if len(auth) <= 0 {
		log.Printf("user login error,name:%s passwd:%s", userName, passWord)
		cp.callLog.OnError("ERR_AUTH_STR", "user authentication error")
		time.Sleep(15 * time.Second)
		return
	}
	cp.tunLock.Lock()
	cp.authStr = auth[0]
	cp.tunLock.Unlock()
	log.Printf("update auth complete")
	buf := make([]byte, res.ContentLength)
	off := 0
	for {
		n, err := res.Body.Read(buf[off:])
		if n == 0 && err != nil {
			break
		}
		off += n
		if off >= len(buf) {
			break
		}
	}
	var msg servMsg
	err = json.Unmarshal(buf, &msg)
	if err != nil {
		return
	}
	svr = msg.Servers
	return
}

func (cp *clientProxy) startWebSocketClient(callLog CallLogInterface) {
	go func() {
		last := time.Now()
		timer := time.NewTicker(time.Second)
		lastLiveBytes := atomic.LoadInt64(&cp.livePorxy.DownloadBytes)
		lastVodBytes := atomic.LoadInt64(&cp.vodPorxy.DownloadBytes)
		for {
			select {
			case <-timer.C:
				cLiveBytes := atomic.LoadInt64(&cp.livePorxy.DownloadBytes)
				cVodBytes := atomic.LoadInt64(&cp.vodPorxy.DownloadBytes)
				usetime := time.Since(last) / time.Millisecond
				liveSpeed := (cLiveBytes - lastLiveBytes) * 1000 / int64(usetime)
				vodSpeed := (cVodBytes - lastVodBytes) * 1000 / int64(usetime)
				atomic.StoreInt64(&cp.liveSpeed, liveSpeed)
				atomic.StoreInt64(&cp.vodSpeed, vodSpeed)
				lastLiveBytes = cLiveBytes
				lastVodBytes = cVodBytes
			}
		}

	}()
	signKey := getDecHashStr()
	servers := strings.Split(getDecAPIServers(), ",")
	if len(servers) <= 0 {
		log.Printf("Error auth server empty")
		callLog.OnError("ERR_AUTH_SVR_DATA", "auth servers reply empty data")
		return
	}
	//	servers = []string{"secret-3.magisapk.com:1925", "secret-3.magistv.net:1926"}
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})
	for {
		for _, svr := range servers {
			webServers, err := cp.getWebSocketServers(signKey, fmt.Sprintf("https://%s/api/websocket/getSecrets", svr))
			if len(webServers) <= 0 {
				if err != nil {
					log.Printf("%s", err)
					callLog.OnError("ERR_CON_AUTH_SVR", fmt.Sprintf("%x", sha1.Sum([]byte(svr))))
					//		log.Printf("connect auth server failed,wait 3s")
					time.Sleep(time.Duration(3+rand.Int()%10) * time.Second)
				} else {
					callLog.OnError("ERR_GET_EMPTY_AUTH_SVR", fmt.Sprintf("%x", sha1.Sum([]byte(svr))))
					//		log.Printf("get auth server failed,wait 15s")
					time.Sleep(time.Duration(5+rand.Int()%10) * time.Second)
				}
				continue
			}
			rand.Shuffle(len(webServers), func(i, j int) {
				webServers[i], webServers[j] = webServers[j], webServers[i]
			})
			for i := 0; i < 20; i++ {
				sv := webServers[rand.Int()%len(webServers)]
				url := fmt.Sprintf("wss://%s/api/websocket/connect", sv)
				cp.runWebSocketClient(url, signKey, callLog)
				callLog.OnError("ERR_AUTH_CON_PROXY", fmt.Sprintf("%x", sha1.Sum([]byte(sv))))
				//		log.Printf("get auth server failed,wait 5s")
				time.Sleep(time.Duration(3+rand.Int()%10) * time.Second)
			}
			//	log.Printf("update auth key failed,wait 5s")
			time.Sleep(5 * time.Second)
		}
	}
}

func (cp *clientProxy) onLiveProxyRequest(w http.ResponseWriter, r *http.Request) bool {
	cp.callLog.OnLog("LIVE", r.RequestURI)
	if r.Method != "GET" && r.Method != "PUT" {
		w.WriteHeader(403)
		w.Write([]byte("forbidden,method not supported\n"))
		return false
	}
	var err error
	idx := strings.Index(r.RequestURI, "?")
	if idx > 0 {
		r.RequestURI = r.RequestURI[:idx]
	}
	agent := r.Header["User-Agent"]
	if len(agent) <= 0 {
		w.WriteHeader(403)
		return false
	}
	start := time.Now()
	auth := ""
	for {
		if time.Since(start) > 30*time.Second {
			w.WriteHeader(500)
			return false
		}

		cp.tunLock.Lock()
		auth = cp.authStr
		cp.tunLock.Unlock()
		if len(auth) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
		//	log.Printf("live wait for auth")
	}

	r.Header.Set("Accept", "*/*")
	timestr := fmt.Sprintf("%d", time.Now().Unix())
	ss := getDecHashStr() + r.URL.Path + agent[0] + cp.userName + timestr + auth
	mac := hmac.New(sha256.New, []byte(auth))
	mac.Write([]byte(ss))
	sbyte := mac.Sum(nil)
	signstr := base62.EncodeToString(sbyte)
	r.RequestURI = fmt.Sprintf(getDecS3Str(), r.RequestURI, cp.userName, timestr, signstr)
	//	log.Printf("live url query:%s", r.RequestURI)
	r.URL, err = url.Parse(r.RequestURI)
	if err != nil {
		w.WriteHeader(403)
		w.Write([]byte("invalid url"))
		return false
	}
	return true
}

func (cp *clientProxy) onVodProxyRequest(w http.ResponseWriter, r *http.Request) bool {
	cp.callLog.OnLog("VOD", r.RequestURI)
	if r.Method != "GET" && r.Method != "PUT" {
		w.WriteHeader(403)
		w.Write([]byte("forbidden,method not supported\n"))
		return false
	}
	var err error
	idx := strings.Index(r.RequestURI, "?")
	if idx > 0 {
		r.RequestURI = r.RequestURI[:idx]
	}
	agent := r.Header["User-Agent"]
	if len(agent) <= 0 {
		w.WriteHeader(403)
		return false
	}
	start := time.Now()
	auth := ""
	for {
		if time.Since(start) > 30*time.Second {
			w.WriteHeader(500)
			return false
		}

		cp.tunLock.Lock()
		auth = cp.authStr
		cp.tunLock.Unlock()
		if len(auth) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
		//	log.Printf("live wait for auth")
	}

	r.Header.Set("Accept", "*/*")
	timestr := fmt.Sprintf("%d", time.Now().Unix())
	ss := getDecHashStr() + r.URL.Path + agent[0] + cp.userName + timestr + auth
	mac := hmac.New(sha256.New, []byte(auth))
	mac.Write([]byte(ss))
	sbyte := mac.Sum(nil)
	signstr := base62.EncodeToString(sbyte)
	r.RequestURI = fmt.Sprintf(getDecS2Str(), r.RequestURI, cp.userName, timestr, signstr)
	//	log.Printf("vod url query:%s", r.RequestURI)
	r.URL, err = url.Parse(r.RequestURI)
	if err != nil {
		w.WriteHeader(403)
		w.Write([]byte("invalid url"))
		return false
	}
	return true
}

func runPostLog(lchan chan logData) {
	lclient := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				nport := "80"
				id := strings.Index(addr, ":")
				if id > 0 {
					nport = addr[id+1:]
					addr = addr[:id]
				}
				ips := goproxy.GetHostsByName(addr)
				if len(ips) <= 0 {
					return nil, errors.New("dns resolve error")
				}
				addr = fmt.Sprintf("%s:%s", ips[rand.Int()%len(ips)], nport)
				c, err := net.DialTimeout(netw, addr, time.Second*10)
				if err != nil {
					return nil, err
				}
				return c, nil
			},
			ResponseHeaderTimeout: 20 * time.Second,
			IdleConnTimeout:       120 * time.Second,
			Proxy: func(req *http.Request) (*url.URL, error) {
				//	return http.ProxyFromEnvironment(req)
				return nil, nil
			},
			// TODO: Make this configurable later on? The default of 2 is too low.
			// goals: (1) new connections should not be opened and closed frequently, (2) we should not run out of sockets.
			// This doesn't seem to need much tuning. The number of connections open at a given time seems to be less than 500, even when sending hundreds of pushes per second.
			MaxIdleConnsPerHost: 3,
			DisableCompression:  true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	postfn := func(ustr, bstr string) {
		req, err := http.NewRequest("POST", ustr, strings.NewReader(bstr))
		if err != nil {
			log.Printf("Log http req:%s err:%s", ustr, err)
			return
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Connection", "keep-alive")
		if req.Body != nil {
			defer req.Body.Close()
		}

		res, err := lclient.Do(req)
		if err != nil {
			log.Printf("Log http req:%s err:%s", ustr, err)
			return
		}
		if res.Body != nil {
			defer res.Body.Close()
		}
		if res.StatusCode != 200 {
			log.Printf("Log post failed url:%s data:%s", ustr, bstr)
			return
		}
		log.Printf("Log post success url:%s data:%s", ustr, bstr)
	}
	for {
		select {
		case lc := <-lchan:
			postfn(lc.requrl, lc.str)
		}
	}
}

type logData struct {
	requrl string
	str    string
}

var (
	apiLock sync.Mutex
	logChan chan logData
)

//GetHostByName api dns-resovler
func GetHostByName(host string) string {
	id := strings.Index(host, ":")
	if id > 0 {
		host = host[:id]
	}
	ips := goproxy.GetHostsByName(host)
	addrs := ""
	for _, ip := range ips {
		addrs += ip + ","
	}
	return addrs
}

//PostLogData post logs
func PostLogData(req, str string) {
	if len(req) <= 0 || len(str) <= 0 {
		log.Printf("Log post paramter empty,ignore")
		return
	}
	apiLock.Lock()
	if logChan == nil {
		logChan = make(chan logData, 128)
		go runPostLog(logChan)
	}
	apiLock.Unlock()

	if len(logChan) < cap(logChan)-1 {
		dt := logData{
			requrl: req,
			str:    str,
		}
		logChan <- dt
	} else {
		log.Printf("Log req:%s body:%s request queue full,drop msg", req, str)
	}
}

// GetUpdateAddrs get apk update address  https://test1.com/test1.apk,https://test2.com/test2.apk,
func GetUpdateAddrs() string {
	var addrs string
	clientLock.Lock()
	if pclient == nil {
		clientLock.Unlock()
		return addrs
	}
	for _, str := range pclient.updateURLs {
		addrs += str + ","
	}
	clientLock.Unlock()
	return addrs
}

// GetVodProxyAddress use this address set application http proxy to use this
func GetVodProxyAddress() string {
	return fmt.Sprintf("http://127.0.0.1:%d", pclient.vodPort)
}

// GetLiveProxyAddress use this address set application http proxy to use this
func GetLiveProxyAddress() string {
	return fmt.Sprintf("http://127.0.0.1:%d", pclient.livePort)
}

//IsOpened check
func IsOpened() bool {
	b := false
	clientLock.Lock()
	if pclient != nil {
		b = true
	}
	clientLock.Unlock()
	return b
}

// StartProxy main method
func StartProxy(usernm, passwd string, vodPort, livePort int, call CallLogInterface) int {
	rand.Seed(int64(time.Now().Unix()))
	call.OnLog("VERSION-INFO", tunVersion)
	log.Printf("start new client proxy,version:%s", tunVersion)
	clientLock.Lock()
	if pclient != nil {
		clientLock.Unlock()
		log.Printf("proxy already started")
		return -1
	}
	log.Printf("start new client proxy vodPort:%d livePort:%d", vodPort, livePort)
	client := new(clientProxy)
	client.tunMsgChan = make(chan *webMsg, 128)
	fmtstr := getDecS1Str()

	var err1, err2 error
	client.vodPort = vodPort
	client.vodProxyAddr = fmt.Sprintf(fmtstr, vodPort)
	client.vodPorxy = goproxy.New()
	client.vodPorxy.OnNewRequest = client.onVodProxyRequest
	client.vodTunLis, err1 = net.Listen("tcp", client.vodProxyAddr)

	client.livePort = livePort
	client.liveProxyAddr = fmt.Sprintf(fmtstr, livePort)
	client.livePorxy = goproxy.New()
	client.livePorxy.OnNewRequest = client.onLiveProxyRequest
	client.liveTunLis, err2 = net.Listen("tcp", client.liveProxyAddr)
	if err1 != nil || err2 != nil {
		clientLock.Unlock()
		log.Printf("proxy start err1:%s err2:%s", err1, err2)
		return -2
	}
	go func() {
		proxy := &http.Server{
			Handler:           client.vodPorxy,
			ReadHeaderTimeout: 60 * time.Second,
			ReadTimeout:       12 * time.Hour,
			WriteTimeout:      12 * time.Hour,
		}
		err := proxy.Serve(client.vodTunLis)
		log.Printf("Start live tun proxy Server error:%s", err)
	}()
	go func() {
		proxy := &http.Server{
			Handler:           client.livePorxy,
			ReadHeaderTimeout: 60 * time.Second,
			ReadTimeout:       12 * time.Hour,
			WriteTimeout:      12 * time.Hour,
		}
		err := proxy.Serve(client.liveTunLis)
		log.Printf("Start vod tun proxy Server error:%s", err)
	}()

	client.callLog = call
	client.userName = usernm
	client.passWD = passwd
	pclient = client
	clientLock.Unlock()
	go pclient.startWebSocketClient(call)
	time.Sleep(time.Second)
	return 0
}
