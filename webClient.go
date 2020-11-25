package resProxy

import (
	"log"

	"github.com/gorilla/websocket"
)

type tunServer struct {
	TimeSync     int64  `json:"timeSync"`
	MaxBandwidth int64  `json:"maxBandWidth"`
	MaxCli       int    `json:"maxClient"`
	IPAddr       string `json:"ip"`
	VodStPort    int    `json:"vodStPort"`
	VodEtPort    int    `json:"vodEtPort"`
	LiveStPort   int    `json:"liveStPort"`
	LiveEtPort   int    `json:"liveEtPort"`
}

type speedTestReply struct {
	Adrr       string   `json:"addr"`
	ResolveIPS []string `json:"svrips"`
	ConSecs    int      `json:"conSecs"`
	UseTime    int      `json:"useTime"`
	MaxSpeed   int      `json:"maxSpeed"`
	AvgSpeed   int      `json:"avgSpeed"`
	MinSpeed   int      `json:"minSpeed"`
	DownBytes  int      `json:"downBytes"`
}

type speedTestData struct {
	UserDev string           `json:"userDev"`
	TestURL string           `json:"testUrl"`
	TimeUTC int              `json:"timeUTC"`
	UserIP  string           `json:"userip"`
	Addrs   []string         `json:"addrs"`
	Replys  []speedTestReply `json:"replys"`
}

type webMsg struct {
	MsgType       string         `json:"type"`
	AuthStr       string         `json:"auth"`
	Version       string         `json:"version"`
	TunIP         string         `json:"tunIP"`
	CurrentTun    string         `json:"curTun"`
	DownloadBytes uint64         `json:"downBytes"`
	DownloadSpeed uint64         `json:"downSpeed"`
	UploadBytes   uint64         `json:"upBytes"`
	UploadSpeed   uint64         `json:"upSpeed"`
	UpdateURLs    []string       `json:"updateURL"`
	TunServers    []tunServer    `json:"tunServers"`
	SpeedTest     *speedTestData `json:"speedTest,omitempty"`
}

type webConn struct {
	conn      *websocket.Conn
	die       chan struct{}
	writeChan chan *webMsg
	readChan  chan *webMsg
}

func (wc *webConn) readWebSocketMsg() {
	defer func() {
		select {
		case <-wc.die:
			return
		default:
			close(wc.die)
		}
	}()
	for {
		select {
		case <-wc.die:
			return
		default:
			msg := webMsg{}
			err := wc.conn.ReadJSON(&msg)
			if err != nil {
				log.Printf("Web socket recv error:%s", err.Error())
				return
			}
			wc.readChan <- &msg
		}
	}
}

func (wc *webConn) writeWebSocketMsg() {
	defer func() {
		select {
		case <-wc.die:
			return
		default:
			close(wc.die)
		}
	}()

	for {
		select {
		case ms := <-wc.writeChan:
			err := wc.conn.WriteJSON(ms)
			if err != nil {
				log.Printf("web socket closed:%s", err.Error())
				return
			}
		case <-wc.die:
			return
		}
	}
}

func (wc *webConn) Close() {
	select {
	case <-wc.die:
	default:
		close(wc.die)
	}
}

func (wc *webConn) startWebSocketCon(msgSize int) {
	wc.die = make(chan struct{})
	wc.readChan = make(chan *webMsg, msgSize)
	wc.writeChan = make(chan *webMsg, msgSize)
	go wc.readWebSocketMsg()
	go wc.writeWebSocketMsg()
}
