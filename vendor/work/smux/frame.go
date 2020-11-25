package smux

import (
	"encoding/binary"
	"fmt"
)

const (
	version             = 2
	LimitFrameCacheSize = 100000
	LimitStreamSize     = 100000
)

const ( // cmds
	cmdNOP byte = iota // session keep alive
	cmdCLS             // session close
	cmdSYN             // stream open
	cmdFIN             // stream close, a.k.a EOF mark
	cmdPSH             // data push
	cmdACK             // data ack
)

/*
cmdACK
sid frameindex | sid frameindex | sid frameindex | sid frameindex
*/
const (
	sizeOfVer    = 1
	sizeOfCmd    = 1
	sizeOfLength = 2
	sizeOfSid    = 4
	sizeOfFid    = 4
	headerSize   = sizeOfVer + sizeOfCmd + sizeOfSid + sizeOfFid + sizeOfLength
)

// Frame defines a packet from or to be multiplexed into a single connection
type Frame struct {
	ver  byte
	cmd  byte
	len  uint16
	sid  uint32
	fid  uint32
	data []byte
}

type frameAck struct {
	sid  uint32
	fid  uint32
	size int
}

func newFrame(cmd byte, sid uint32, fid uint32) Frame {
	return Frame{ver: version, cmd: cmd, sid: sid, fid: fid}
}

type rawHeader [headerSize]byte

func (h rawHeader) Version() byte {
	return h[0]
}

func (h rawHeader) Cmd() byte {
	return h[1]
}

func (h rawHeader) Length() uint16 {
	return binary.LittleEndian.Uint16(h[2:])
}

func (h rawHeader) StreamID() uint32 {
	return binary.LittleEndian.Uint32(h[4:])
}

func (h rawHeader) FrameID() uint32 {
	return binary.LittleEndian.Uint32(h[8:])
}

func (h rawHeader) String() string {
	return fmt.Sprintf("Version:%d Cmd:%d StreamID:%d Length:%d",
		h.Version(), h.Cmd(), h.StreamID(), h.Length())
}
