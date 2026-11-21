package proxyproto

import (
	"container/list"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// maxUDPDatagramSize is the largest payload a UDP datagram can carry (65535
// minus the IPv4/UDP headers). Buffers handed to the underlying PacketConn are
// sized to it so no datagram is truncated by the reader.
const maxUDPDatagramSize = 65535

// defaultUDPMaxFlows bounds the client-to-proxy table by default. Each entry is
// created by a datagram, so an unbounded table would let a peer sending
// spoofed headers grow memory without limit.
const defaultUDPMaxFlows = 4096

// ErrNoUDPFlow indicates that UDPPacketConn.WriteTo was asked to reply to an
// address it has not seen in a previously accepted datagram. The flow table is
// the only mapping from a header-declared client address back to the proxy that
// relayed for it, so an unknown address cannot be routed.
var ErrNoUDPFlow = errors.New("proxyproto: no proxy flow for UDP client address")

// UDPPacketConnOptions configures a UDPPacketConn. The zero value is usable.
//
// Options are read-only after NewUDPPacketConn returns; changing them
// afterwards, including through a value retained by the caller, is a data race.
type UDPPacketConnOptions struct {
	// MaxFlows bounds the client-to-proxy table; the least recently used entry
	// is evicted when the limit is reached. Values <= 0 use
	// defaultUDPMaxFlows.
	MaxFlows int
	// DropHook, if set, is called for every datagram that is discarded because
	// it did not carry a complete, valid PROXY header. It runs on the reading
	// goroutine and must not block.
	DropHook func(remote net.Addr, err error)
}

// UDPPacketConn wraps a net.PacketConn whose peers prefix every datagram with
// a PROXY protocol header, per spec section 2.
//
// Unlike Conn, it is packet-oriented: each ReadFrom consumes exactly one
// datagram, parses at most one header out of that datagram, and returns the
// proxied payload as that datagram's contents. A header is never completed
// with bytes from the next datagram, and the next datagram is never consumed
// trying to finish a truncated one. Datagrams without a complete, valid header
// are discarded (the spec forbids guessing whether a header is present) and the
// read continues with the next datagram; DropHook observes each discard.
//
// ReadFrom reports the client address carried by the header, except for LOCAL
// datagrams, where it reports the relaying proxy itself. WriteTo accepts an
// address previously returned by ReadFrom and routes the reply to the proxy
// that relayed for it; replies carry no header.
//
// The methods are safe for concurrent use, matching net.PacketConn: concurrent
// ReadFrom calls use independent pooled buffers, WriteTo and the flow table are
// mutex-protected, deadlines are delegated to the underlying connection, and
// Close may race with any of them.
type UDPPacketConn struct {
	conn     net.PacketConn
	maxFlows int
	dropHook func(remote net.Addr, err error)

	mu    sync.Mutex
	flows map[string]*list.Element
	order *list.List // front is the oldest entry, evicted first

	pool sync.Pool
}

type udpFlow struct {
	key   string
	proxy net.Addr
}

// UDPPacketConn implements net.PacketConn.
var _ net.PacketConn = (*UDPPacketConn)(nil)

// NewUDPPacketConn wraps conn with PROXY protocol datagram parsing. It accepts
// a single optional UDPPacketConnOptions value; passing more than one is a
// programming error and panics.
func NewUDPPacketConn(conn net.PacketConn, options ...UDPPacketConnOptions) *UDPPacketConn {
	var opts UDPPacketConnOptions
	switch len(options) {
	case 0:
	case 1:
		opts = options[0]
	default:
		panic("proxyproto: NewUDPPacketConn accepts at most one UDPPacketConnOptions value")
	}
	maxFlows := opts.MaxFlows
	if maxFlows <= 0 {
		maxFlows = defaultUDPMaxFlows
	}
	c := &UDPPacketConn{
		conn:     conn,
		maxFlows: maxFlows,
		dropHook: opts.DropHook,
		flows:    make(map[string]*list.Element),
		order:    list.New(),
	}
	c.pool.New = func() any {
		buf := make([]byte, maxUDPDatagramSize)
		return &buf
	}
	return c
}

// ReadFrom reads one datagram, parses its PROXY header, and copies the proxied
// payload into p. It returns the client address carried by the header, or the
// relaying proxy's own address for LOCAL datagrams.
//
// Like net.UDPConn.ReadFrom, a payload longer than p is truncated to len(p) and
// the remainder is discarded. An accepted datagram with no payload returns
// (0, addr, nil). Datagrams that do not carry a complete, valid header are
// dropped and the next datagram is read; the underlying read deadline still
// applies, so a stream of invalid datagrams cannot postpone a timeout.
func (c *UDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, _, err := c.ReadFromProxy(p)
	return n, addr, err
}

// ReadFromProxy behaves like ReadFrom and additionally returns the parsed
// header, so callers can inspect TLVs or the destination address. The header is
// not retained by the connection, and it never aliases a pooled read buffer.
func (c *UDPPacketConn) ReadFromProxy(p []byte) (int, net.Addr, *Header, error) {
	for {
		buf := c.pool.Get().(*[]byte)
		n, proxyAddr, err := c.conn.ReadFrom(*buf)
		if err != nil {
			c.pool.Put(buf)
			return 0, nil, nil, err
		}

		header, payload, err := ParseUDPDatagram((*buf)[:n])
		if err != nil {
			// The datagram is consumed and ignored; its bytes can never be
			// combined with the next datagram. The buffer goes back to the pool
			// only after the parse, and payload only aliases it until then.
			c.pool.Put(buf)
			if c.dropHook != nil {
				c.dropHook(proxyAddr, err)
			}
			continue
		}

		// ParseUDPDatagram's payload aliases the pooled buffer, so copy into the
		// caller's slice and drop the header (which holds its own copies of the
		// addresses and TLVs) before returning the buffer for reuse.
		copied := copy(p, payload)
		clientAddr := udpClientAddr(header, proxyAddr)
		c.remember(clientAddr, proxyAddr)
		c.pool.Put(buf)

		return copied, clientAddr, header, nil
	}
}

// WriteTo sends p as a headerless reply to an address previously returned by
// ReadFrom, routing it to the proxy that relayed for that client.
func (c *UDPPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, ErrNoUDPFlow
	}
	key := udpAddrKey(addr)

	c.mu.Lock()
	var proxy net.Addr
	if element, ok := c.flows[key]; ok {
		// Move to the back so frequently used flows survive eviction.
		c.order.MoveToBack(element)
		proxy = element.Value.(*udpFlow).proxy
	}
	c.mu.Unlock()

	if proxy == nil {
		return 0, fmt.Errorf("%w: %s", ErrNoUDPFlow, addr)
	}
	return c.conn.WriteTo(p, proxy)
}

// Close closes the underlying packet connection.
func (c *UDPPacketConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the underlying socket's local address.
func (c *UDPPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDeadline sets the read and write deadlines on the underlying connection.
func (c *UDPPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *UDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (c *UDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Raw returns the underlying PacketConn.
func (c *UDPPacketConn) Raw() net.PacketConn {
	return c.conn
}

// udpClientAddr reports the address ReadFrom returns for a parsed header. A
// LOCAL datagram (or one without source information) belongs to the proxy
// itself; no address from inside the header is substituted, so an unspecified
// or fake address can never masquerade as a real client.
func udpClientAddr(header *Header, proxy net.Addr) net.Addr {
	if header.Command.IsLocal() || header.SourceAddr == nil {
		return proxy
	}
	return header.SourceAddr
}

// udpAddrKey identifies an address independently of the concrete pointer, so a
// caller may reconstruct the address (as net.PacketConn callers commonly do)
// and still match a flow.
func udpAddrKey(addr net.Addr) string {
	return addr.Network() + "|" + addr.String()
}

// remember records that proxy relays for client, evicting the least recently
// used flow when the table is full.
func (c *UDPPacketConn) remember(client, proxy net.Addr) {
	key := udpAddrKey(client)

	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.flows[key]; ok {
		element.Value.(*udpFlow).proxy = proxy
		c.order.MoveToBack(element)
		return
	}
	if c.order.Len() >= c.maxFlows {
		oldest := c.order.Front()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.flows, oldest.Value.(*udpFlow).key)
		}
	}
	c.flows[key] = c.order.PushBack(&udpFlow{key: key, proxy: proxy})
}
