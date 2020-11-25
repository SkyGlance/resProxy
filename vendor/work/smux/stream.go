package smux

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
)

// Stream implements net.Conn
type Stream struct {
	id            uint32
	rstflag       int32
	sess          *Session
	buffer        *bytes.Buffer
	bufferLock    sync.Mutex
	ackRecvBuf    []frameAck
	frameSize     int
	chReadEvent   chan struct{} // notify a read event
	chWritEvent   chan struct{}
	die           chan struct{} // flag the stream has closed
	dieLock       sync.Mutex
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	dataLock   sync.Mutex
	frameIndex uint32
	ackSendBuf []frameAck
}

// newStream initiates a Stream struct
func newStream(id uint32, frameSize int, sess *Session) *Stream {
	s := new(Stream)
	s.id = id
	s.chReadEvent = make(chan struct{}, 1)
	s.chWritEvent = make(chan struct{}, 1)
	s.frameSize = frameSize
	s.sess = sess
	s.die = make(chan struct{})
	s.frameIndex = 218
	s.buffer = new(bytes.Buffer)
	return s
}

// ID returns the unique stream ID.
func (s *Stream) ID() uint32 {
	return s.id
}

// Read implements net.Conn
func (s *Stream) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		select {
		case <-s.die:
			return 0, errors.New(errBrokenPipe)
		default:
			return 0, nil
		}
	}

	var deadline <-chan time.Time
	if d, ok := s.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

READ:
	s.bufferLock.Lock()
	n, err = s.buffer.Read(b)
	s.bufferLock.Unlock()

	if n > 0 {
		s.sess.returnTokens(n)
		return n, nil
	} else if atomic.LoadInt32(&s.rstflag) == 1 {
		_ = s.Close()
		return 0, io.EOF
	}

	select {
	case <-s.chReadEvent:
		goto READ
	case <-deadline:
		return n, errTimeout
	case <-s.die:
		return 0, errors.New(errBrokenPipe)
	}
}

// Write implements net.Conn
func (s *Stream) Write(b []byte) (n int, err error) {
	var deadline <-chan time.Time
	if d, ok := s.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}
	if atomic.LoadInt32(&s.rstflag) == 1 {
		_ = s.Close()
		return 0, io.EOF
	}
	sent := 0
	bts := b
	for len(bts) > 0 {
		s.frameIndex++
		f := newFrame(cmdPSH, s.id, s.frameIndex)
		sz := len(bts)
		if sz > s.frameSize {
			sz = s.frameSize
		}
		f.data = bts[:sz]
		bts = bts[sz:]
		req := writeData{
			frame:  f,
			result: make(chan writeResult, 1),
		}
		//log.Printf("Write new frame,sid:%d fid:%d len:%d", s.id, s.frameIndex, len(f.data))

		s.dataLock.Lock()
		checklen := 0
		for _, fk := range s.ackSendBuf {
			checklen += fk.size
		}
		fc := frameAck{
			fid:  f.fid,
			size: len(f.data),
		}
		s.ackSendBuf = append(s.ackSendBuf, fc)
		s.dataLock.Unlock()
		if checklen >= s.sess.config.MaxStreamSendBuf ||
			len(s.ackSendBuf) >= s.sess.config.MaxFrameSndPerStream {
			//	log.Printf("streamid:%d write stop", s.id)
			select {
			case <-s.chWritEvent:
			case <-s.die:
				return sent, errors.New(errBrokenPipe)
			case <-deadline:
				return sent, errTimeout
			}
		}

		select {
		case s.sess.writeDataChan <- req:
		case <-s.die:
			return sent, errors.New(errBrokenPipe)
		case <-deadline:
			return sent, errTimeout
		}

		select {
		case result := <-req.result:
			sent += result.n
			if result.err != nil {
				return sent, result.err
			}
		case <-s.die:
			return sent, errors.New(errBrokenPipe)
		case <-deadline:
			return sent, errTimeout
		}
		//log.Printf("send fid:%d", f.fid)
	}
	return sent, nil
}

// Close implements net.Conn
func (s *Stream) Close() error {
	s.dieLock.Lock()

	select {
	case <-s.die:
		s.dieLock.Unlock()
		return errors.New(errBrokenPipe)
	default:
		close(s.die)
		s.dieLock.Unlock()
		s.sess.streamClosed(s.id)
		_, err := s.sess.writeFrame(newFrame(cmdFIN, s.id, 0))
		return err
	}
}

// GetDieCh returns a readonly chan which can be readable
// when the stream is to be closed.
func (s *Stream) GetDieCh() <-chan struct{} {
	return s.die
}

// SetReadDeadline sets the read deadline as defined by
// net.Conn.SetReadDeadline.
// A zero time value disables the deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	//	log.Printf("Stream set read deadline:%s", t.String())
	s.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline sets the write deadline as defined by
// net.Conn.SetWriteDeadline.
// A zero time value disables the deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	//	log.Printf("Stream set write deadline:%s", t.String())
	s.writeDeadline.Store(t)
	return nil
}

// SetDeadline sets both read and write deadlines as defined by
// net.Conn.SetDeadline.
// A zero time value disables the deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	//log.Printf("Stream set deadline:%s", t.String())
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	if err := s.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// session closes the stream
func (s *Stream) sessionClose() {
	s.dieLock.Lock()
	defer s.dieLock.Unlock()

	select {
	case <-s.die:
	default:
		close(s.die)
	}
}

// LocalAddr satisfies net.Conn interface
func (s *Stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

// RemoteAddr satisfies net.Conn interface
func (s *Stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

func (s *Stream) pushAcks(idxs []uint32) error {
	s.dataLock.Lock()
	if len(s.ackSendBuf) <= 0 {
		s.dataLock.Unlock()
		s.Close()
		log.Printf("stream:%d read data sync error recv:%d\n",
			s.id, len(idxs))
		return fmt.Errorf("read no sync data")
	}
	for _, idx := range idxs {
		if len(s.ackSendBuf) <= 0 {
			s.dataLock.Unlock()
			s.Close()
			log.Printf("stream:%d read data sync missmatch", s.id)
			return fmt.Errorf("read sync data missmatch")
		}
		f := s.ackSendBuf[0]
		if f.fid != idx {
			s.dataLock.Unlock()
			s.Close()
			log.Printf("stream:%d read data sync missmatch current:%d recv:%d",
				s.id, f.fid, idx)
			return fmt.Errorf("read sync data missmatch")
		}
		//log.Printf("Ack recv,sid:%d fid:%d", s.id, idx)
		s.ackSendBuf = s.ackSendBuf[1:]
	}
	//	log.Printf("remove fid:%d", fidx)
	s.dataLock.Unlock()
	s.notifyWriteEvent()
	return nil
}

// pushFrame a slice into buffer
func (s *Stream) pushFrame(f *Frame) {
	s.bufferLock.Lock()
	s.buffer.Write(f.data)
	ack := frameAck{
		sid:  f.sid,
		fid:  f.fid,
		size: len(f.data),
	}
	s.ackRecvBuf = append(s.ackRecvBuf, ack)
	s.bufferLock.Unlock()
}

func (s *Stream) getPushAcks() (acks []frameAck) {
	s.bufferLock.Lock()
	defer s.bufferLock.Unlock()
	nleft := s.sess.config.MaxReceiveBuffer/2 - s.buffer.Len()
	if nleft <= 0 {
		return
	}
	off := 0
	for {
		if len(s.ackRecvBuf) <= 0 {
			break
		}
		f := s.ackRecvBuf[0]
		off += f.size
		acks = append(acks, f)
		s.ackRecvBuf = s.ackRecvBuf[1:]
		if off >= nleft {
			break
		}
	}
	return
}

// recycleTokens transform remaining bytes to tokens(will truncate buffer)
func (s *Stream) recycleTokens() (n int) {
	s.bufferLock.Lock()
	n = s.buffer.Len()
	s.buffer.Reset()
	s.bufferLock.Unlock()
	return
}

// notify read event
func (s *Stream) notifyReadEvent() {
	select {
	case s.chReadEvent <- struct{}{}:
	default:
	}
}

func (s *Stream) notifyWriteEvent() {
	select {
	case s.chWritEvent <- struct{}{}:
	default:
	}
}

// mark this stream has been reset
func (s *Stream) markRST() {
	atomic.StoreInt32(&s.rstflag, 1)
}

var errTimeout error = &timeoutError{}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
