package uot

import (
	"bytes"
	"errors"
	"io"
	"net"
)

// MaxPacketSize is max udp packet size.
const MaxPacketSize = 65535

// Conn is an udp-over-tcp connection.
type Conn interface {
	net.Conn
	// Handshake handle with target address of udp packet.
	// In server side, Handshake receives a nil net.Addr, read and return the target net.Addr.
	// In client side, Handshake receives a non-nil net.Addr, send target address to server.
	Handshake(net.Addr) (net.Addr, error)
}

// PacketConn is client side udp connection.
type PacketConn interface {
	net.PacketConn
	// ReadPacket is similar with ReadFrom.
	// It returns readed packet length, target address of udp packet, remote address, error.
	ReadPacket(p []byte) (n int, target net.Addr, addr net.Addr, err error)
	// WritePacket is similar with WriteTo.
	// It writes packet to addr. target is origin packet addr.
	WritePacket(p []byte, target net.Addr, addr net.Addr) (n int, err error)
}

type defaultConn struct {
	net.Conn
	isClient bool // is client or server side
}

type defaultPacketConn struct {
	net.PacketConn
}

/*
Protocol define of defaultPacketConn:
[addr][payload]
addr: target address of packet,  which is a socks5 address defined in RFC 1928.
payload: raw udp packet.

Protocol define of defaultConn:
[handshake][packet...]
handshake: target address of packet, which is a socks5 address defined in RFC 1928.
packet: [size][payload]
size: 2-byte, length of payload.
payload: raw udp packet.
*/

// DefaultOutConn return a default client side Conn.
func DefaultOutConn(conn net.Conn) Conn {
	return &defaultConn{conn, true}
}

// DefaultInConn return a default server side Conn.
func DefaultInConn(conn net.Conn) Conn {
	return &defaultConn{conn, false}
}

// DefaultPacketConn return a default packet conn.
func DefaultPacketConn(conn net.PacketConn) PacketConn {
	return &defaultPacketConn{conn}
}

func (c *defaultPacketConn) ReadPacket(p []byte) (int, net.Addr, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, nil, err
	}
	// read addr in packet head and remove it.
	target, err := ReadSocksAddr(bytes.NewReader(p[:n]))
	if err != nil {
		return 0, nil, nil, err
	}
	length := len(target)
	copy(p, p[length:n])
	return n - length, target, addr, nil
}

func (c *defaultPacketConn) WritePacket(p []byte, target net.Addr, addr net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, addr)
}

func (c *defaultConn) Handshake(addr net.Addr) (net.Addr, error) {
	if c.isClient {
		target, ok := addr.(SocksAddr)
		if !ok {
			return nil, errors.New("not a socks address")
		}
		_, err := c.Conn.Write(target)
		if err != nil {
			return nil, err
		}
		return addr, nil
	}
	return ReadSocksAddr(c.Conn)
}

// Read read a full udp packet, if b is shorter than packet, return error.
func (c *defaultConn) Read(b []byte) (int, error) {
	if len(b) < 2 {
		return 0, io.ErrShortBuffer
	}
	_, err := io.ReadFull(c.Conn, b[:2])
	if err != nil {
		return 0, err
	}
	n := int(b[0])<<8 | int(b[1])
	if len(b) < n {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.Conn, b[:n])
}

// Write write a full udp packet, if head+b is longer than packet max size, return error.
func (c *defaultConn) Write(b []byte) (int, error) {
	n := len(b)
	if n > MaxPacketSize-2 {
		return 0, errors.New("over max packet size")
	}
	_, err := c.Conn.Write([]byte{byte(n >> 8), byte(n & 0x000000ff)})
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}
