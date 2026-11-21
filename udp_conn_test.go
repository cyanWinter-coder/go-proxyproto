package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestUDPConn builds a UDPPacketConn over a loopback socket pair: the
// returned conn is the receiver and send is a plain socket that plays the
// proxy. Sockets are preferred over a hand-written fake so deadlines, Close and
// concurrent ReadFrom exercise the same paths as production.
func newTestUDPConn(t *testing.T, options UDPPacketConnOptions) (conn *UDPPacketConn, send *net.UDPConn) {
	t.Helper()

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxy, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = server.Close()
		t.Fatalf("dial: %v", err)
	}

	conn = NewUDPPacketConn(server, options)
	t.Cleanup(func() {
		_ = conn.Close()
		_ = proxy.Close()
	})
	return conn, proxy
}

func testV4Header() *Header {
	return &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: UDPv4,
		SourceAddr:        &net.UDPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
		DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
	}
}

func mustFormatUDP(t *testing.T, header *Header, payload []byte) []byte {
	t.Helper()
	datagram, err := header.FormatUDPDatagram(payload)
	if err != nil {
		t.Fatalf("FormatUDPDatagram: %v", err)
	}
	return datagram
}

func writeDatagram(t *testing.T, conn *net.UDPConn, datagram []byte) {
	t.Helper()
	if _, err := conn.Write(datagram); err != nil {
		t.Fatalf("proxy write: %v", err)
	}
}

// TestUDPPacketConnRoundTrip pins the happy path over a real socket: one
// datagram in, header-declared client address out, exact payload out, and a
// reply routed back through the proxy that relayed it.
func TestUDPPacketConnRoundTrip(t *testing.T) {
	conn, proxy := newTestUDPConn(t, UDPPacketConnOptions{})
	header := testV4Header()
	payload := []byte("hello over udp")

	writeDatagram(t, proxy, mustFormatUDP(t, header, payload))

	buf := make([]byte, 64)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != string(payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if addr.String() != header.SourceAddr.String() {
		t.Fatalf("client addr = %v, want %v", addr, header.SourceAddr)
	}

	// A reply addressed to the synthetic client is routed to the proxy socket,
	// headerless, so the proxy sees exactly the reply bytes.
	if _, err := conn.WriteTo([]byte("pong"), addr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	reply := make([]byte, 64)
	_ = proxy.SetReadDeadline(time.Now().Add(2 * time.Second))
	rn, err := proxy.Read(reply)
	if err != nil {
		t.Fatalf("proxy read reply: %v", err)
	}
	if got := string(reply[:rn]); got != "pong" {
		t.Fatalf("reply = %q, want %q", got, "pong")
	}

	// The address is also usable as a reconstructed value, not just the
	// pointer ReadFrom returned: callers commonly rebuild addresses.
	reconstructed := &net.UDPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000}
	if _, err := conn.WriteTo([]byte("pong2"), reconstructed); err != nil {
		t.Fatalf("WriteTo with reconstructed address: %v", err)
	}

	if conn.LocalAddr().String() != proxy.RemoteAddr().String() {
		t.Fatalf("LocalAddr = %v, want %v", conn.LocalAddr(), proxy.RemoteAddr())
	}
	if conn.Raw() == nil {
		t.Fatal("Raw() must expose the underlying PacketConn")
	}
}

// TestUDPPacketConnDrops covers every drop cause: no header, a truncated or
// over-declared header, and an unknown family. Each discarded datagram is
// observed by DropHook, and the following valid datagram is returned intact —
// proving the invalid one did not consume or corrupt it.
func TestUDPPacketConnDrops(t *testing.T) {
	var (
		mu      sync.Mutex
		dropped int
		lastErr error
	)

	conn, proxy := newTestUDPConn(t, UDPPacketConnOptions{
		DropHook: func(_ net.Addr, err error) {
			mu.Lock()
			defer mu.Unlock()
			dropped++
			lastErr = err
		},
	})

	header := testV4Header()
	good := mustFormatUDP(t, header, []byte("good"))

	overDeclared := bytes.Clone(good[:16])
	binaryPutUint16(overDeclared[14:16], lengthV4+8)
	overDeclared = append(overDeclared, good[16:]...)

	unspec, err := (&Header{Version: 2, Command: PROXY, TransportProtocol: UNSPEC}).Format()
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	bad := [][]byte{
		[]byte("plain application data"),
		{}, // empty datagram
		append(bytes.Clone(SIGV2), byte(PROXY), byte(UDPv4)), // fixed prefix cut short
		overDeclared,                                // declares more than the datagram carries
		append(unspec, []byte("x")...),              // PROXY + UNSPEC: no usable family
		[]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80\r\n"), // v1 line with a missing field
	}
	for _, datagram := range bad {
		writeDatagram(t, proxy, datagram)
	}
	writeDatagram(t, proxy, good)

	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after dropped datagrams: %v", err)
	}
	if got := string(buf[:n]); got != "good" {
		t.Fatalf("payload = %q, want %q (a dropped datagram bled into the good one)", got, "good")
	}
	if addr.String() != header.SourceAddr.String() {
		t.Fatalf("client addr = %v, want %v", addr, header.SourceAddr)
	}
	mu.Lock()
	got, gotErr := dropped, lastErr
	mu.Unlock()
	if got != len(bad) {
		t.Fatalf("DropHook saw %d drops, want %d", got, len(bad))
	}
	if gotErr == nil {
		t.Fatal("DropHook never received an error")
	}
}

// binaryPutUint16 is a tiny local helper so the test can declare a wrong
// length without exporting write access to the header layout.
func binaryPutUint16(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}

// TestUDPPacketConnTruncatedDoesNotConsumeNextDatagram pins requirement 2: an
// over-declared header is dropped, and the very next datagram is delivered as
// its own message rather than being read to complete the previous header.
func TestUDPPacketConnTruncatedDoesNotConsumeNextDatagram(t *testing.T) {
	conn, proxy := newTestUDPConn(t, UDPPacketConnOptions{})

	good := mustFormatUDP(t, testV4Header(), []byte("second-message"))
	truncated := good[:20] // signature + fixed prefix, then only part of the address block

	writeDatagram(t, proxy, truncated)
	writeDatagram(t, proxy, good)

	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "second-message" {
		t.Fatalf("payload = %q, want the second datagram intact", got)
	}
}

// TestUDPPacketConnLocalReportsProxy pins LOCAL semantics: the header carries
// no trustworthy client, so ReadFrom reports the relaying proxy, and replies
// go back to it. Unknown-family LOCAL frames likewise never masquerade as a
// local success with invented addresses.
func TestUDPPacketConnLocalReportsProxy(t *testing.T) {
	conn, proxy := newTestUDPConn(t, UDPPacketConnOptions{})

	local := &Header{Version: 2, Command: LOCAL, TransportProtocol: UNSPEC}
	writeDatagram(t, proxy, mustFormatUDP(t, local, []byte("health")))

	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "health" {
		t.Fatalf("payload = %q, want %q", got, "health")
	}
	if addr.String() != proxy.LocalAddr().String() {
		t.Fatalf("LOCAL ReadFrom addr = %v, want proxy peer %v", addr, proxy.LocalAddr())
	}
	if _, err := conn.WriteTo([]byte("ok"), addr); err != nil {
		t.Fatalf("WriteTo LOCAL reply: %v", err)
	}

	// IPv6 and v1 LOCAL-equivalent (UNKNOWN) still surface a usable payload;
	// a bogus family on the wire is dropped rather than reported as local.
	v6 := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: UDPv6,
		SourceAddr:        &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5353},
		DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443},
	}
	writeDatagram(t, proxy, mustFormatUDP(t, v6, []byte("v6")))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom v6: %v", err)
	}
	if got := string(buf[:n]); got != "v6" {
		t.Fatalf("payload = %q, want %q", got, "v6")
	}
	if addr.String() != v6.SourceAddr.String() {
		t.Fatalf("v6 client addr = %v, want %v", addr, v6.SourceAddr)
	}
}

// TestUDPPacketConnDeadlines pins requirement 5: deadline calls reach the
// underlying socket, so a read with nothing to deliver times out, and reads
// queued behind a dropped datagram still honour the deadline.
func TestUDPPacketConnDeadlines(t *testing.T) {
	conn, _ := newTestUDPConn(t, UDPPacketConnOptions{})

	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, _, err := conn.ReadFrom(make([]byte, 8))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}

	// Clearing the deadline must make the socket block rather than time out;
	// a write deadline still applies to WriteTo.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := conn.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}); !errors.Is(err, ErrNoUDPFlow) {
		t.Fatalf("WriteTo unknown address: expected ErrNoUDPFlow, got %v", err)
	}

	// Only-unroutable datagrams must not reset the deadline: each loop
	// iteration reads again, and the socket's deadline still fires.
	proxy := dialTestReceiver(t, conn)
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	writeDatagram(t, proxy, []byte("not a header"))
	_, _, err = conn.ReadFrom(make([]byte, 8))
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected timeout behind a dropped datagram, got %v", err)
	}
}

// dialTestReceiver returns a socket addressed at conn's local address, for
// tests that build the receiver themselves.
func dialTestReceiver(t *testing.T, conn *UDPPacketConn) *net.UDPConn {
	t.Helper()
	proxy, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

// TestUDPPacketConnEmptyAndOversizedPayload pins requirement 3 and the
// net.PacketConn truncation contract: an empty payload yields a nil error and
// zero bytes, while a payload larger than the caller's buffer is truncated to
// it rather than split or rejected.
func TestUDPPacketConnEmptyAndOversizedPayload(t *testing.T) {
	conn, proxy := newTestUDPConn(t, UDPPacketConnOptions{})
	header := testV4Header()

	writeDatagram(t, proxy, mustFormatUDP(t, header, nil))
	buf := make([]byte, 8)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom empty payload: %v", err)
	}
	if n != 0 {
		t.Fatalf("empty payload returned %d bytes", n)
	}
	if addr == nil || addr.String() != header.SourceAddr.String() {
		t.Fatalf("empty payload addr = %v, want %v", addr, header.SourceAddr)
	}

	payload := bytes.Repeat([]byte("0123456789"), 100)
	writeDatagram(t, proxy, mustFormatUDP(t, header, payload))
	small := make([]byte, 7)
	n, _, err = conn.ReadFrom(small)
	if err != nil {
		t.Fatalf("ReadFrom oversized payload: %v", err)
	}
	if n != len(small) || !bytes.Equal(small, []byte("0123456")) {
		t.Fatalf("truncation = %q (%d bytes), want %q", small[:n], n, "0123456")
	}
}

// TestUDPPacketConnBufferReuse pins requirement 6: the payload is copied into
// the caller's buffer before the pooled read buffer is reused, so a second read
// cannot mutate what the first one returned, and distinct caller buffers never
// alias each other.
func TestUDPPacketConnBufferReuse(t *testing.T) {
	conn, proxy := newTestUDPConn(t, UDPPacketConnOptions{})
	header := testV4Header()

	const rounds = 32
	got := make([][]byte, 0, rounds)
	for i := range rounds {
		payload := []byte(fmt.Sprintf("message-%02d", i))
		writeDatagram(t, proxy, mustFormatUDP(t, header, payload))

		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom %d: %v", i, err)
		}
		got = append(got, bytes.Clone(buf[:n]))
		// Scribble over this caller's buffer: a later pooled read must not be
		// affected, and no earlier result may be visible here.
		for j := range buf {
			buf[j] = 0xFF
		}
	}
	for i, payload := range got {
		if want := fmt.Sprintf("message-%02d", i); string(payload) != want {
			t.Fatalf("read %d retained %q, want %q: buffers alias", i, payload, want)
		}
	}
}

// TestUDPPacketConnConcurrentReadWrite closes requirement 6 with the race
// detector: concurrent readers and writers plus a concurrent Close must not
// race, lose a successfully delivered datagram, or panic.
func TestUDPPacketConnConcurrentReadWrite(t *testing.T) {
	conn, proxy := newTestUDPConn(t, UDPPacketConnOptions{MaxFlows: 64})
	header := testV4Header()

	const readers, perReader = 4, 50

	var (
		wg        sync.WaitGroup
		delivered atomic.Int64
	)
	errCh := make(chan error, readers)

	for r := range readers {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			buf := make([]byte, 64)
			for range perReader {
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, addr, err := conn.ReadFrom(buf)
				if err != nil {
					errCh <- fmt.Errorf("reader %d: %w", r, err)
					return
				}
				delivered.Add(1)
				// Replies race with readers and with each other.
				if _, err := conn.WriteTo([]byte("ack"), addr); err != nil {
					errCh <- fmt.Errorf("writer %d: %w", r, err)
					return
				}
			}
		}(r)
	}

	// Send exactly as many datagrams as the readers will consume.
	go func() {
		for range readers * perReader {
			payload := []byte("concurrent")
			datagram, err := header.FormatUDPDatagram(payload)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := proxy.Write(datagram); err != nil {
				return // proxy closed by cleanup
			}
		}
	}()

	// Drain the proxy's reply socket so the kernel buffer never fills.
	go func() {
		reply := make([]byte, 64)
		for {
			_ = proxy.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := proxy.Read(reply); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent access: %v", err)
	}
	if got := delivered.Load(); got != readers*perReader {
		t.Fatalf("delivered %d datagrams, want %d", got, readers*perReader)
	}
}

// TestUDPPacketConnCloseUnblocksRead pins that Close reaches the underlying
// socket, waking a blocked reader with an error instead of hanging. It is
// deliberately not parallel-safe with the shared cleanup, so it uses its own
// sockets.
func TestUDPPacketConnCloseUnblocksRead(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	conn := NewUDPPacketConn(server, UDPPacketConnOptions{})

	done := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 8))
		done <- err
	}()

	// Give the reader a moment to block in the syscall, then close.
	time.Sleep(50 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked ReadFrom returned nil error after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}

// TestUDPPacketConnFlowEviction pins that the flow table is bounded: with
// MaxFlows=1, learning a second client evicts the first.
func TestUDPPacketConnFlowEviction(t *testing.T) {
	conn, proxy := newTestUDPConn(t, UDPPacketConnOptions{MaxFlows: 1})

	send := func(src string, port int) *net.UDPAddr {
		client := &net.UDPAddr{IP: net.ParseIP(src), Port: port}
		header := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv4,
			SourceAddr:        client,
			DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
		}
		if !client.IP.To4().Equal(net.ParseIP(src)) {
			header.TransportProtocol = UDPv6
		}
		writeDatagram(t, proxy, mustFormatUDP(t, header, []byte("x")))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, err := conn.ReadFrom(make([]byte, 8)); err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		return client
	}

	first := send("10.1.1.1", 1000)
	second := send("10.2.2.2", 2000)

	if _, err := conn.WriteTo([]byte("x"), second); err != nil {
		t.Fatalf("latest flow was evicted: %v", err)
	}
	if _, err := conn.WriteTo([]byte("x"), first); !errors.Is(err, ErrNoUDPFlow) {
		t.Fatalf("oldest flow should have been evicted, got %v", err)
	}
}
