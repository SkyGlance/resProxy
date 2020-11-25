// Copyright 2018 ouqiang authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package goproxy HTTP(S)代理, 支持中间人代理解密HTTPS数据
package goproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"work/pkgs/cert"

	"github.com/miekg/dns"
)

const (
	// 连接目标服务器超时时间
	defaultTargetConnectTimeout = 60 * time.Second
	// 目标服务器读写超时时间
	defaultTargetReadWriteTimeout = 24 * 3600 * time.Second
	// 客户端读写超时时间
	defaultClientReadWriteTimeout = 24 * 3600 * time.Second
)

type dnsMsgData struct {
	last time.Time
	ips  []string
}

var (
	// 隧道连接成功响应行
	tunnelEstablishedResponseLine = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
	badGateway                    = []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", http.StatusBadGateway, http.StatusText(http.StatusBadGateway)))

	hmlk        sync.Mutex
	hmap        map[string]*dnsMsgData
	nameservers []string
	expireTime  time.Duration
)

func isIP(ip string) bool {
	return (net.ParseIP(ip) != nil)
}

// 生成隧道建立请求行
func makeTunnelRequestLine(addr string) string {
	return fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", addr)
}

type options struct {
	disableKeepAlive bool
	delegate         Delegate
	decryptHTTPS     bool
	certCache        cert.Cache
	transport        *http.Transport
}

//Option 选项
type Option func(*options)

// WithDisableKeepAlive 连接是否重用
func WithDisableKeepAlive(disableKeepAlive bool) Option {
	return func(opt *options) {
		opt.disableKeepAlive = disableKeepAlive
	}
}

// WithDelegate 设置委托类
func WithDelegate(delegate Delegate) Option {
	return func(opt *options) {
		opt.delegate = delegate
	}
}

// WithTransport 自定义http transport
func WithTransport(t *http.Transport) Option {
	return func(opt *options) {
		opt.transport = t
	}
}

// WithDecryptHTTPS 中间人代理, 解密HTTPS, 需实现证书缓存接口
func WithDecryptHTTPS(c cert.Cache) Option {
	return func(opt *options) {
		opt.decryptHTTPS = true
		opt.certCache = c
	}
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

	hfn := func() (rev []string) {
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
			hmlk.Lock()
			hmap[domain] = nmd
			hmlk.Unlock()
		} else {
			log.Printf("Domain:%s refresh ips failed\n", domain)
		}
		return nmd.ips
	}

	hmlk.Lock()
	res, ok := hmap[domain]
	if ok {
		ips = make([]string, len(res.ips))
		copy(ips, res.ips)
		hmlk.Unlock()
		if time.Since(res.last) <= expireTime {
			log.Printf("Domain:%s IP refresh\n", domain)
			go hfn()
		}
		return
	}
	hmlk.Unlock()
	return hfn()
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

// New 创建proxy实例
func New(opt ...Option) *Proxy {
	opts := &options{}
	for _, o := range opt {
		o(opts)
	}
	if opts.delegate == nil {
		opts.delegate = &DefaultDelegate{}
	}
	if opts.transport == nil {
		opts.transport = &http.Transport{
			DialTLS: func(netw, addr string) (net.Conn, error) {
				nport := "443"
				id := strings.Index(addr, ":")
				if id > 0 {
					nport = addr[id+1:]
					addr = addr[:id]
				}
				ips := GetHostsByName(addr)
				if len(ips) <= 0 {
					return nil, fmt.Errorf("dns resolve host:%s failed", addr)
				}
				host := fmt.Sprintf("%s:%s", ips[rand.Int()%len(ips)], nport)
				c, err := net.DialTimeout(netw, host, time.Second*15)
				if err != nil {
					return nil, err
				}
				if sr, ok := c.(*net.TCPConn); ok {
					sr.SetReadBuffer(8 * 1024 * 1024)
				}
				conf := &tls.Config{
					ServerName:         addr,
					InsecureSkipVerify: false,
				}
				tlsConn := tls.Client(c, conf)
				err = tlsConn.Handshake()
				if err != nil {
					c.Close()
					log.Printf("handshake tls sess failed,err:%s\n", err.Error())
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
				ips := GetHostsByName(addr)
				if len(ips) <= 0 {
					log.Printf("dns resolve host:%s failed", addr)
					return nil, errors.New("dns resolve error")
				}
				addr = fmt.Sprintf("%s:%s", ips[rand.Int()%len(ips)], nport)
				c, err := net.DialTimeout(netw, addr, time.Second*15)
				if err != nil {
					return nil, err
				}
				if sr, ok := c.(*net.TCPConn); ok {
					sr.SetReadBuffer(8 * 1024 * 1024)
				}
				return c, nil
			},

			//	DisableKeepAlives:     true,
			MaxIdleConns:          1000,
			IdleConnTimeout:       9000 * time.Second,
			TLSHandshakeTimeout:   1000 * time.Second,
			ExpectContinueTimeout: 100 * time.Second,
			Proxy: func(req *http.Request) (*url.URL, error) {
				//	return http.ProxyFromEnvironment(req)
				return nil, nil
			},
		}
	}

	p := &Proxy{}
	p.delegate = opts.delegate
	p.decryptHTTPS = opts.decryptHTTPS
	if p.decryptHTTPS {
		p.cert = &cert.Certificate{
			Cache: opts.certCache,
		}
	}
	p.transport = opts.transport
	p.transport.DisableKeepAlives = opts.disableKeepAlive
	p.transport.Proxy = p.delegate.ParentProxy

	return p
}

// Proxy 实现了http.Handler接口
type Proxy struct {
	UPloadBytes   int64
	DownloadBytes int64
	clientConnNum int32
	delegate      Delegate
	decryptHTTPS  bool
	cert          *cert.Certificate
	transport     *http.Transport
	OnNewRequest  func(rw http.ResponseWriter, req *http.Request) bool
}

var _ http.Handler = &Proxy{}

// ServeHTTP 实现了http.Handler接口
func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if p.OnNewRequest != nil {
		if !p.OnNewRequest(rw, req) {
			return
		}
	}
	atomic.AddInt32(&p.clientConnNum, 1)
	defer func() {
		atomic.AddInt32(&p.clientConnNum, -1)
	}()
	ctx := &Context{
		Req:  req,
		Data: make(map[interface{}]interface{}),
	}
	defer p.delegate.Finish(ctx)
	p.delegate.Connect(ctx, rw)
	if ctx.abort {
		//	log.Printf("proxy err1")
		return
	}
	p.delegate.Auth(ctx, rw)
	if ctx.abort {
		//	log.Printf("proxy err2")
		return
	}
	//	log.Printf("Method:%s URL:%s", ctx.Req.Method, ctx.Req.URL)
	switch {
	case ctx.Req.Method == http.MethodConnect && p.decryptHTTPS:
		p.forwardHTTPS(ctx, rw)
	case ctx.Req.Method == http.MethodConnect:
		p.forwardTunnel(ctx, rw)
	default:
		p.forwardHTTP(ctx, rw)
	}
}

// ClientConnNum 获取客户端连接数
func (p *Proxy) ClientConnNum() int32 {
	return atomic.LoadInt32(&p.clientConnNum)
}

// DoRequest 执行HTTP请求，并调用responseFunc处理response
func (p *Proxy) DoRequest(ctx *Context, responseFunc func(*http.Response, error)) {
	if ctx.Data == nil {
		ctx.Data = make(map[interface{}]interface{})
	}
	p.delegate.BeforeRequest(ctx)
	if ctx.abort {
		return
	}
	newReq := new(http.Request)
	*newReq = *ctx.Req
	newReq.Header = CloneHeader(newReq.Header)
	removeConnectionHeaders(newReq.Header)
	for _, item := range hopHeaders {
		if newReq.Header.Get(item) != "" {
			newReq.Header.Del(item)
		}
	}
	//	newReq.Header.Set("Connection", "close")
	resp, err := p.transport.RoundTrip(newReq)
	p.delegate.BeforeResponse(ctx, resp, err)
	if ctx.abort {
		return
	}
	if err == nil {
		removeConnectionHeaders(resp.Header)
		for _, h := range hopHeaders {
			resp.Header.Del(h)
		}
	}
	responseFunc(resp, err)
}

func chunked(te []string) bool { return len(te) > 0 && te[0] == "chunked" }

// HTTP转发
func (p *Proxy) forwardHTTP(ctx *Context, rw http.ResponseWriter) {
	ctx.Req.URL.Scheme = "http"
	//log.Printf("ctx header:%v", ctx.Req.Header)
	p.DoRequest(ctx, func(resp *http.Response, err error) {
		if err != nil {
			//	log.Printf("%s - HTTP请求错误: , 错误: %s", ctx.Req.URL, err)
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		CopyHeader(rw.Header(), resp.Header)
		rw.Header().Set("Connection", "close")
		rw.WriteHeader(resp.StatusCode)
		//log.Printf("resp code:%d header:%v", resp.StatusCode, resp.Header)
		//log.Printf("write header:%v", rw.Header())
		newcopy := func() {
			f, ok := rw.(http.Flusher)
			if ok {
				f.Flush()
			}
			buf := make([]byte, 512000, 512000)
			for {
				n, err := resp.Body.Read(buf)
				if n <= 0 && err != nil {
					if err != io.EOF {
						//		log.Printf("%s - HTTP response写入客户端失败, %s", ctx.Req.URL, err)
					}
					return
				}
				_, err = rw.Write(buf[:n])
				if err != nil {
					return
				}
				atomic.AddInt64(&p.DownloadBytes, int64(n))
				if ok {
					f.Flush()
				}
			}
		}
		newcopy()
		resp.Body.Close()
	})
}

// HTTPS转发
func (p *Proxy) forwardHTTPS(ctx *Context, rw http.ResponseWriter) {
	clientConn, err := hijacker(rw)
	if err != nil {
		p.delegate.ErrorLog(err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer clientConn.Close()
	_, err = clientConn.Write(tunnelEstablishedResponseLine)
	if err != nil {
		log.Printf("%s - HTTPS解密, 通知客户端隧道已连接失败, %s", ctx.Req.URL.Host, err)
		return
	}
	tlsConfig, err := p.cert.Generate(ctx.Req.URL.Host)
	if err != nil {
		log.Printf("%s - HTTPS解密, 生成证书失败: %s", ctx.Req.URL.Host, err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	tlsClientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	defer tlsClientConn.Close()
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("%s - HTTPS解密, 握手失败: %s", ctx.Req.URL.Host, err)
		return
	}
	buf := bufio.NewReader(tlsClientConn)
	tlsReq, err := http.ReadRequest(buf)
	if err != nil {
		if err != io.EOF {
			log.Printf("%s - HTTPS解密, 读取客户端请求失败: %s", ctx.Req.URL.Host, err)
		}
		return
	}
	tlsReq.RemoteAddr = ctx.Req.RemoteAddr
	tlsReq.URL.Scheme = "https"
	tlsReq.URL.Host = tlsReq.Host
	ctx.Req = tlsReq

	p.DoRequest(ctx, func(resp *http.Response, err error) {
		if err != nil {
			log.Printf("%s - HTTPS解密, 请求错误: %s", ctx.Req.URL, err)
			tlsClientConn.Write(badGateway)
			return
		}
		rw.Header().Set("Connection", "keep-alive")
		rw.WriteHeader(resp.StatusCode)
		//log.Printf("resp code:%d header:%v", resp.StatusCode, resp.Header)
		//log.Printf("write header:%v", rw.Header())
		newcopy := func() {
			f, ok := rw.(http.Flusher)
			if ok {
				f.Flush()
			}
			buf := make([]byte, 512000, 512000)
			for {
				n, err := resp.Body.Read(buf)
				if n <= 0 && err != nil {
					if err != io.EOF {
						log.Printf("%s - HTTPS response写入客户端失败, %s", ctx.Req.URL, err)
					}
					return
				}
				_, err = rw.Write(buf[:n])
				if err != nil {
					return
				}
				atomic.AddInt64(&p.DownloadBytes, int64(n))
				if ok {
					f.Flush()
				}
			}
		}
		newcopy()
		resp.Body.Close()
	})
}

// 隧道转发
func (p *Proxy) forwardTunnel(ctx *Context, rw http.ResponseWriter) {
	clientConn, err := hijacker(rw)
	if err != nil {
		p.delegate.ErrorLog(err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer clientConn.Close()
	parentProxyURL, err := p.delegate.ParentProxy(ctx.Req)
	if err != nil {
		log.Printf("%s - 解析代理地址错误: %s", ctx.Req.URL.Host, err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	targetAddr := ctx.Req.URL.Host
	if parentProxyURL != nil {
		targetAddr = parentProxyURL.Host
	}
	if len(nameservers) > 0 {
		dport := "80"
		idx := strings.Index(targetAddr, ":")
		if idx > 0 {
			dport = targetAddr[idx+1:]
			targetAddr = targetAddr[:idx]
		}
		ips := GetHostsByName(targetAddr)
		if len(ips) <= 0 {
			log.Printf("%s - 解析DNS地址错误: %s", ctx.Req.URL.Host, targetAddr)
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		targetAddr = fmt.Sprintf("%s:%s", ips[rand.Int()%len(ips)], dport)
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, defaultTargetConnectTimeout)
	if err != nil {
		log.Printf("%s - 隧道转发连接目标服务器失败: %s", ctx.Req.URL.Host, err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	clientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	targetConn.SetDeadline(time.Now().Add(defaultTargetReadWriteTimeout))
	if parentProxyURL == nil {
		_, err = clientConn.Write(tunnelEstablishedResponseLine)
		if err != nil {
			log.Printf("%s - 隧道连接成功,通知客户端错误: %s", ctx.Req.URL.Host, err)
			return
		}
	} else {
		tunnelRequestLine := makeTunnelRequestLine(ctx.Req.URL.Host)
		targetConn.Write([]byte(tunnelRequestLine))
	}
	p.transfer(clientConn, targetConn)
}

// 双向转发
func (p *Proxy) transfer(src net.Conn, dst net.Conn) {
	go func() {
		buf := make([]byte, 512000, 512000)
		for {
			n, err := dst.Read(buf)
			if n <= 0 && err != nil {
				break
			}
			_, err = src.Write(buf[:n])
			if err != nil {
				break
			}
			atomic.AddInt64(&p.DownloadBytes, int64(n))
		}
		src.Close()
		dst.Close()
	}()

	buf := make([]byte, 512000, 512000)
	for {
		n, err := src.Read(buf)
		if n <= 0 && err != nil {
			break
		}
		_, err = dst.Write(buf[:n])
		if err != nil {
			break
		}
		atomic.AddInt64(&p.UPloadBytes, int64(n))
	}
	dst.Close()
	src.Close()
}

// 获取底层连接
func hijacker(rw http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("web server不支持Hijacker")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijacker错误: %s", err)
	}

	return conn, nil
}

// CopyHeader 浅拷贝Header
func CopyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// CloneHeader 深拷贝Header
func CloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// CloneBody 拷贝Body
func CloneBody(b io.ReadCloser) (r io.ReadCloser, body []byte, err error) {
	if b == nil {
		return http.NoBody, nil, nil
	}
	body, err = ioutil.ReadAll(b)
	if err != nil {
		return http.NoBody, nil, err
	}
	r = ioutil.NopCloser(bytes.NewReader(body))

	return r, body, nil
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeConnectionHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}
