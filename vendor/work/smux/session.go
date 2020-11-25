package smux

import (
	"encoding/binary"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
)

const (
	defaultAcceptBacklog = 512
)

const (
	errBrokenPipe      = "broken pipe"
	errInvalidProtocol = "invalid protocol version"
	errGoAway          = "stream id overflows, should start a new connection"
	errTooMany         = "too many connections"
)

type writeData struct {
	frame  Frame
	result chan writeResult
}

type writeResult struct {
	n   int
	err error
}

// Session defines a multiplexed connection for streams
type Session struct {
	dataReady int64 // flag data has arrived

	conn io.ReadWriteCloser

	config       *Config
	nextStreamID uint32 // next stream identifier

	bucket       int32         // token bucket
	bucketNotify chan struct{} // used for waiting for tokens

	streams    map[uint32]*Stream // all streams in this session
	streamLock sync.Mutex         // locks streams

	die       chan struct{} // flag session has died
	dieLock   sync.Mutex
	chAccepts chan *Stream

	deadline atomic.Value

	writeDataChan chan writeData
}

func newSession(config *Config, conn io.ReadWriteCloser, client bool) *Session {
	s := new(Session)
	s.die = make(chan struct{})
	s.conn = conn
	s.config = config
	s.streams = make(map[uint32]*Stream)
	s.chAccepts = make(chan *Stream, defaultAcceptBacklog)
	s.bucket = int32(config.MaxReceiveBuffer)
	s.bucketNotify = make(chan struct{}, 1)

	s.writeDataChan = make(chan writeData, config.MaxFrameSndCache)

	if client {
		s.nextStreamID = 1
	} else {
		s.nextStreamID = 0
	}
	go s.recvLoop()
	go s.sendLoop()
	return s
}

// OpenStream is used to create a new stream
func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, errors.New(errBrokenPipe)
	}
	// generate stream id
	s.streamLock.Lock()
	if len(s.streams) >= LimitStreamSize {
		s.streamLock.Unlock()
		return nil, errors.New(errTooMany)
	}
	for {
		s.nextStreamID += 2
		_, ok := s.streams[s.nextStreamID]
		if !ok {
			break
		}
	}
	sid := s.nextStreamID
	s.streamLock.Unlock()

	stream := newStream(sid, s.config.MaxFrameSize, s)
	if _, err := s.writeFrame(newFrame(cmdSYN, sid, 0)); err != nil {
		return nil, errors.Wrap(err, "writeFrame")
	}
	s.streamLock.Lock()
	s.streams[sid] = stream
	s.streamLock.Unlock()
	return stream, nil
}

// AcceptStream is used to block until the next available stream
// is ready to be accepted.
func (s *Session) AcceptStream() (*Stream, error) {
	var deadline <-chan time.Time
	if d, ok := s.deadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}
	select {
	case stream := <-s.chAccepts:
		return stream, nil
	case <-deadline:
		return nil, errTimeout
	case <-s.die:
		return nil, errors.New(errBrokenPipe)
	}
}

// Close is used to close the session and all streams.
func (s *Session) Close() (err error) {
	s.dieLock.Lock()
	select {
	case <-s.die:
		s.dieLock.Unlock()
		return errors.New(errBrokenPipe)
	default:
		close(s.die)
		s.dieLock.Unlock()
		s.streamLock.Lock()
		for k := range s.streams {
			s.streams[k].sessionClose()
		}
		s.streamLock.Unlock()
		s.notifyBucket()
		return s.conn.Close()
	}
}

// notifyBucket notifies recvLoop that bucket is available
func (s *Session) notifyBucket() {
	select {
	case s.bucketNotify <- struct{}{}:
	default:
	}
}

// IsClosed does a safe check to see if we have shutdown
func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// NumStreams returns the number of currently open streams
func (s *Session) NumStreams() int {
	if s.IsClosed() {
		return 0
	}
	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	return len(s.streams)
}

// SetDeadline sets a deadline used by Accept* calls.
// A zero time value disables the deadline.
func (s *Session) SetDeadline(t time.Time) error {
	log.Printf("Muxer set deadline:%s", t.String())
	s.deadline.Store(t)
	return nil
}

// notify the session that a stream has closed
func (s *Session) streamClosed(sid uint32) {
	s.streamLock.Lock()
	if n := s.streams[sid].recycleTokens(); n > 0 { // return remaining tokens to the bucket
		if atomic.AddInt32(&s.bucket, int32(n)) > 0 {
			s.notifyBucket()
		}
	}
	delete(s.streams, sid)
	s.streamLock.Unlock()
}

// returnTokens is called by stream to return token after read
func (s *Session) returnTokens(n int) {
	if atomic.AddInt32(&s.bucket, int32(n)) > 0 {
		s.notifyBucket()
	}
}

// session read a frame from underlying connection
// it's data is pointed to the input buffer
func (s *Session) readFrame(buffer []byte) (f Frame, err error) {
	var hdr rawHeader
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return f, errors.Wrap(err, "readFrame")
	}

	if hdr.Version() != version {
		return f, errors.New(errInvalidProtocol)
	}

	f.ver = hdr.Version()
	f.cmd = hdr.Cmd()
	f.sid = hdr.StreamID()
	f.fid = hdr.FrameID()
	if length := hdr.Length(); length > 0 {
		f.len = length
		f.data = buffer[:length]
		if _, err := io.ReadFull(s.conn, f.data); err != nil {
			return f, errors.Wrap(err, "readFrame")
		}
	}
	return f, nil
}

func (s *Session) parseAckFrame(f *Frame) (aks []frameAck, err error) {
	if len(f.data)%8 != 0 {
		return aks, errors.New("parse data ack error")
	}
	start := 0
	for {
		if start >= len(f.data) {
			break
		}
		ak := frameAck{
			sid: binary.LittleEndian.Uint32(f.data[start : start+4]),
			fid: binary.LittleEndian.Uint32(f.data[start+4 : start+8]),
		}
		aks = append(aks, ak)
		start += 8
	}
	return
}

// recvLoop keeps on reading from underlying connection if tokens are available
func (s *Session) recvLoop() {
	buffer := make([]byte, 1<<16)
	for {
		for atomic.LoadInt32(&s.bucket) <= 0 && !s.IsClosed() {
			log.Printf("Recv buffer full")
			<-s.bucketNotify
		}
		f, err := s.readFrame(buffer)
		if err != nil {
			s.Close()
			log.Printf("Muxer read frame err:%s", err.Error())
			return
		}
		atomic.StoreInt64(&s.dataReady, time.Now().Unix())
		switch f.cmd {
		case cmdNOP:
		case cmdCLS:
			s.Close()
			return
		case cmdSYN:
			s.streamLock.Lock()
			if _, ok := s.streams[f.sid]; !ok {
				stream := newStream(f.sid, s.config.MaxFrameSize, s)
				s.streams[f.sid] = stream
				select {
				case s.chAccepts <- stream:
				case <-s.die:
				}
			}
			s.streamLock.Unlock()
		case cmdFIN:
			s.streamLock.Lock()
			if stream, ok := s.streams[f.sid]; ok {
				stream.markRST()
				stream.notifyReadEvent()
			}
			s.streamLock.Unlock()
		case cmdPSH:
			//	log.Printf("new data, sid:%d fild:%d", f.sid, f.fid)
			s.streamLock.Lock()
			stream, ok := s.streams[f.sid]
			if ok {
				atomic.AddInt32(&s.bucket, -int32(len(f.data)))
				stream.pushFrame(&f)
				stream.notifyReadEvent()
			}
			s.streamLock.Unlock()
		case cmdACK:
			//log.Printf("Session recv ack data:%d", len(f.data))
			facks, err := s.parseAckFrame(&f)
			if err != nil {
				log.Printf("Pase ack error:%s", err.Error())
				s.Close()
				return
			}
			var sacks []*syncAck
			for _, fak := range facks {
				bfound := false
				for _, nak := range sacks {
					if nak.sid == fak.sid {
						nak.fids = append(nak.fids, fak.fid)
						bfound = true
						break
					}
				}
				if !bfound {
					naks := &syncAck{
						sid: fak.sid,
					}
					naks.fids = append(naks.fids, fak.fid)
					sacks = append(sacks, naks)
				}
			}

			s.streamLock.Lock()
			for _, sak := range sacks {
				if stream, ok := s.streams[sak.sid]; ok {
					err = stream.pushAcks(sak.fids)
					if err != nil {
						s.streamLock.Unlock()
						s.Close()
						return
					}
					//log.Printf("sid:%d frm:%d", fak.sid, fak.fid)
				}
			}
			s.streamLock.Unlock()
		default:
			log.Printf("Muxer Unknown cmd:%d", f.cmd)
			s.Close()
			return
		}
	}
}

func (s *Session) sendLoop() {
	buf := make([]byte, (1<<16)+headerSize)
	maxAckSize := (s.config.MaxFrameSize/8)*8 - 8
	tmpBuf := make([]byte, maxAckSize)
	timer := time.NewTicker(s.config.MaxFrameSndAckTimer)
	defer timer.Stop()

	tickerPing := time.NewTicker(s.config.KeepAliveInterval)
	defer tickerPing.Stop()
	lastwriteTime := time.Now()
	timeout := int64(s.config.KeepAliveTimeout / time.Second)
	for {
		select {
		case <-tickerPing.C:
			if (time.Now().Unix() - atomic.LoadInt64(&s.dataReady)) > timeout {
				log.Printf("Session Read timeout")
				s.Close()
				return
			}
			if time.Since(lastwriteTime) < s.config.KeepAliveInterval {
				break
			}
			f := newFrame(cmdNOP, 0, 0)
			buf[0] = f.ver
			buf[1] = f.cmd
			binary.LittleEndian.PutUint16(buf[2:], 0)
			binary.LittleEndian.PutUint32(buf[4:], f.sid)
			binary.LittleEndian.PutUint32(buf[8:], f.fid)
			n, err := s.conn.Write(buf[:headerSize])
			if n != headerSize || err != nil {
				log.Printf("Write session data failed,n:%d err:%s", n, err.Error())
				s.Close()
				return
			}
			lastwriteTime = time.Now()

		case <-timer.C:
			var ackBuf []frameAck
			s.streamLock.Lock()
			for _, st := range s.streams {
				acks := st.getPushAcks()
				for _, f := range acks {
					ackBuf = append(ackBuf, f)
				}
			}
			s.streamLock.Unlock()
			for {
				if len(ackBuf) <= 0 {
					break
				}
				idx := 0
				offset := 0
				for _, ack := range ackBuf {
					binary.LittleEndian.PutUint32(tmpBuf[offset:], ack.sid)
					binary.LittleEndian.PutUint32(tmpBuf[offset+4:], ack.fid)
					offset += 8
					idx++
					//log.Printf("Session send ack,sid:%d fid:%d", ack.sid, ack.fid)
					if offset >= maxAckSize {
						break
					}
				}
				ackBuf = ackBuf[idx:]
				if offset <= 0 {
					break
				}
				buf[0] = version
				buf[1] = cmdACK
				binary.LittleEndian.PutUint16(buf[2:], uint16(offset))
				binary.LittleEndian.PutUint32(buf[4:], 0)
				binary.LittleEndian.PutUint32(buf[8:], 0)
				copy(buf[headerSize:], tmpBuf[:offset])
				sendlen := headerSize + offset
				n, err := s.conn.Write(buf[:sendlen])
				if n != sendlen || err != nil {
					s.Close()
					log.Printf("Write session sync header failed,n:%d err:%s", n, err.Error())
					return
				}
				//log.Printf("Session send acksize:%d", offset)
				lastwriteTime = time.Now()
			}
		case <-s.die:
			return
		case request := <-s.writeDataChan:
			//	log.Printf("write frame fid:%d", request.frame.fid)
			buf[0] = request.frame.ver
			buf[1] = request.frame.cmd
			binary.LittleEndian.PutUint16(buf[2:], uint16(len(request.frame.data)))
			binary.LittleEndian.PutUint32(buf[4:], request.frame.sid)
			binary.LittleEndian.PutUint32(buf[8:], request.frame.fid)
			copy(buf[headerSize:], request.frame.data)
			sendlen := headerSize + len(request.frame.data)
			n, err := s.conn.Write(buf[:sendlen])
			if n != sendlen || err != nil {
				log.Printf("Write session data failed,n:%d err:%s", n, err.Error())
				s.Close()
				return
			}
			//log.Printf("Session Write frame,sid:%d fid:%d", request.frame.sid, request.frame.fid)
			n -= headerSize
			result := writeResult{
				n:   n,
				err: err,
			}
			request.result <- result
			close(request.result)
			lastwriteTime = time.Now()
		}
	}
}

// writeFrame writes the frame to the underlying connection
// and returns the number of bytes written if successful
func (s *Session) writeFrame(f Frame) (n int, err error) {
	req := writeData{
		frame:  f,
		result: make(chan writeResult, 1),
	}
	select {
	case <-s.die:
		return 0, errors.New(errBrokenPipe)
	case s.writeDataChan <- req:
	}

	select {
	case result := <-req.result:
		return result.n, result.err
	case <-s.die:
		return 0, errors.New(errBrokenPipe)
	}
}
