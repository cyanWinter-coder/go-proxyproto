package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	IPv4AddressesAndPorts        = strings.Join([]string{testLocalhostIP4Addr, testLocalhostIP4Addr, strconv.Itoa(testValidPort), strconv.Itoa(testValidPort)}, separator)
	IPv4In6AddressesAndPorts     = strings.Join([]string{testLocalhostIP4In6Addr, testLocalhostIP4In6Addr, strconv.Itoa(testValidPort), strconv.Itoa(testValidPort)}, separator)
	IPv4AddressesAndInvalidPorts = strings.Join([]string{testLocalhostIP4Addr, testLocalhostIP4Addr, strconv.Itoa(testInvalidPort), strconv.Itoa(testInvalidPort)}, separator)
	IPv6AddressesAndPorts        = strings.Join([]string{testLocalhostIP6Addr, testLocalhostIP6Addr, strconv.Itoa(testValidPort), strconv.Itoa(testValidPort)}, separator)
	IPv6LongAddressesAndPorts    = strings.Join([]string{testIP6LongAddr, testIP6LongAddr, strconv.Itoa(testValidPort), strconv.Itoa(testValidPort)}, separator)

	fixtureTCP4V1    = "PROXY TCP4 " + IPv4AddressesAndPorts + crlf + "GET /"
	fixtureTCP6V1    = "PROXY TCP6 " + IPv6AddressesAndPorts + crlf + "GET /"
	fixtureTCP4IN6V1 = "PROXY TCP6 " + IPv4In6AddressesAndPorts + crlf + "GET /"

	fixtureTCP6V1Overflow = "PROXY TCP6 " + IPv6LongAddressesAndPorts

	fixtureUnknown              = "PROXY UNKNOWN" + crlf
	fixtureUnknownWithAddresses = "PROXY UNKNOWN " + IPv4AddressesAndInvalidPorts + crlf

	fixtureTCP6IPv4SrcIPv4Dst = "PROXY TCP6 192.0.2.1 192.0.2.2 1234 5678" + crlf
	fixtureTCP6IPv6SrcIPv4Dst = "PROXY TCP6 2001:db8::1 192.0.2.1 51512 22" + crlf
	fixtureTCP6IPv4SrcIPv6Dst = "PROXY TCP6 192.0.2.1 2001:db8::1 51512 22" + crlf
)

var invalidParseV1Tests = []struct {
	desc          string
	reader        *bufio.Reader
	expectedError error
}{
	{
		desc:          "no signature",
		reader:        newBufioReader([]byte(testNoProtocol)),
		expectedError: ErrNoProxyProtocol,
	},
	{
		desc:          "prox",
		reader:        newBufioReader([]byte("PROX")),
		expectedError: ErrNoProxyProtocol,
	},
	{
		desc:          "proxy lf",
		reader:        newBufioReader([]byte("PROXY \n")),
		expectedError: ErrLineMustEndWithCrlf,
	},
	{
		desc:          "proxy crlf",
		reader:        newBufioReader([]byte("PROXY " + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "proxy no space crlf",
		reader:        newBufioReader([]byte("PROXY" + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "proxy something crlf",
		reader:        newBufioReader([]byte("PROXY SOMETHING" + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	{
		desc:          "incomplete signature TCP4",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv4AddressesAndPorts)),
		expectedError: ErrCantReadVersion1Header,
	},
	{
		desc:          "invalid IP address",
		reader:        newBufioReader([]byte("PROXY TCP4 invalid invalid 65533 65533" + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with IPv6 addresses",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv6AddressesAndPorts + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with IPv4 mapped addresses",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv4In6AddressesAndPorts + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP6 with invalid address",
		reader:        newBufioReader([]byte("PROXY TCP6 not-an-ip ::1 1234 5678" + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP4 with invalid port",
		reader:        newBufioReader([]byte("PROXY TCP4 " + IPv4AddressesAndInvalidPorts + crlf)),
		expectedError: ErrInvalidPortNumber,
	},
	{
		desc:          "header too long",
		reader:        newBufioReader([]byte("PROXY UNKNOWN " + IPv6LongAddressesAndPorts + " " + crlf)),
		expectedError: ErrVersion1HeaderTooLong,
	},
	{
		desc:          "TCP4 with signed port",
		reader:        newBufioReader([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 +80 443" + crlf)),
		expectedError: ErrInvalidPortNumber,
	},
	{
		desc:          "TCP4 with leading-zero port",
		reader:        newBufioReader([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 080 443" + crlf)),
		expectedError: ErrInvalidPortNumber,
	},
	{
		desc:          "TCP4 with empty port token",
		reader:        newBufioReader([]byte("PROXY TCP4 1.2.3.4 5.6.7.8  443" + crlf)),
		expectedError: ErrInvalidPortNumber,
	},
	{
		desc:          "TCP4 with trailing token",
		reader:        newBufioReader([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443 extra" + crlf)),
		expectedError: ErrCantReadAddressFamilyAndProtocol,
	},
	// The signature dispatch in Read only peeks the first 5 bytes, so the parser
	// itself must reject a first token that is not exactly "PROXY".
	{
		desc:          "signature with trailing garbage",
		reader:        newBufioReader([]byte("PROXYjunk TCP4 1.2.3.4 5.6.7.8 80 443" + crlf)),
		expectedError: ErrCantReadVersion1Header,
	},
	{
		desc:          "signature glued to protocol",
		reader:        newBufioReader([]byte("PROXYTCP4 1.2.3.4 5.6.7.8 80 443" + crlf)),
		expectedError: ErrCantReadVersion1Header,
	},
	// The spec's address grammar has no zone identifiers; netip would accept
	// and silently strip them, forwarding an address the sender never wrote.
	{
		desc:          "TCP6 with zoned source address",
		reader:        newBufioReader([]byte("PROXY TCP6 fe80::1%eth0 fe80::2 80 443" + crlf)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP6 with zoned destination address",
		reader:        newBufioReader([]byte("PROXY TCP6 fe80::1 fe80::2%eth0 80 443" + crlf)),
		expectedError: ErrInvalidAddress,
	},
	// Spec: "Heading zeroes are not permitted in front of numbers in order to
	// avoid any possible confusion with octal numbers." netip enforces this
	// today; the case is pinned so a stdlib change cannot silently loosen it.
	{
		desc:          "TCP4 with leading-zero octet",
		reader:        newBufioReader([]byte("PROXY TCP4 01.2.3.4 5.6.7.8 80 443" + crlf)),
		expectedError: ErrInvalidAddress,
	},
	// Spec: "the advertised protocol family dictates what format to use", so a
	// plain IPv4 literal in a TCP6 line is rejected unless the
	// V1AcceptIPv4InTCP6 compatibility mode is enabled.
	{
		desc:          "TCP6 with plain IPv4 addresses",
		reader:        bufio.NewReader(strings.NewReader(fixtureTCP6IPv4SrcIPv4Dst)),
		expectedError: ErrInvalidAddress,
	},
	{
		desc:          "TCP6 with plain IPv4 destination",
		reader:        bufio.NewReader(strings.NewReader(fixtureTCP6IPv6SrcIPv4Dst)),
		expectedError: ErrInvalidAddress,
	},
}

// TestParseV1IPv4InTCP6Compat pins the V1AcceptIPv4InTCP6 compatibility mode:
// plain IPv4 literals in TCP6 lines (as emitted by e.g. the nginx OSS stream
// module) parse as v4-mapped IPv6 addresses and serialize in ::ffff: form.
func TestParseV1IPv4InTCP6Compat(t *testing.T) {
	V1AcceptIPv4InTCP6 = true
	defer func() { V1AcceptIPv4InTCP6 = false }()

	cases := []struct {
		desc           string
		line           string
		expectedHeader *Header
		expectedWrite  string
	}{
		{
			desc: "TCP6 IPv4 src IPv4 dst",
			line: fixtureTCP6IPv4SrcIPv4Dst,
			expectedHeader: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv6,
				SourceAddr:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1").To16(), Port: 1234},
				DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("192.0.2.2").To16(), Port: 5678},
			},
			// Both addresses are v4-mapped, so both must serialize in ::ffff: form.
			expectedWrite: "PROXY TCP6 ::ffff:192.0.2.1 ::ffff:192.0.2.2 1234 5678" + crlf,
		},
		{
			desc: "TCP6 IPv6 src IPv4 dst",
			line: fixtureTCP6IPv6SrcIPv4Dst,
			expectedHeader: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv6,
				SourceAddr:        &net.TCPAddr{IP: net.ParseIP("2001:db8::1").To16(), Port: 51512},
				DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("192.0.2.1").To16(), Port: 22},
			},
			// Mixed family: genuine IPv6 source stays as-is, v4 dest becomes v4-mapped.
			expectedWrite: "PROXY TCP6 2001:db8::1 ::ffff:192.0.2.1 51512 22" + crlf,
		},
		{
			desc: "TCP6 IPv4 src IPv6 dst",
			line: fixtureTCP6IPv4SrcIPv6Dst,
			expectedHeader: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv6,
				SourceAddr:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1").To16(), Port: 51512},
				DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("2001:db8::1").To16(), Port: 22},
			},
			// Mixed family: v4 source becomes v4-mapped, genuine IPv6 dest stays as-is.
			expectedWrite: "PROXY TCP6 ::ffff:192.0.2.1 2001:db8::1 51512 22" + crlf,
		},
	}
	for _, tt := range cases {
		t.Run(tt.desc, func(t *testing.T) {
			header, err := Read(bufio.NewReader(strings.NewReader(tt.line)))
			if err != nil {
				t.Fatal("unexpected error", err.Error())
			}
			if !header.EqualsTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, header)
			}
			got, err := header.Format()
			if err != nil {
				t.Fatal("unexpected error", err.Error())
			}
			if string(got) != tt.expectedWrite {
				t.Fatalf("expected wire %q, actual %q", tt.expectedWrite, got)
			}
		})
	}
}

// TestFormatV1InvalidPorts pins the format-side port validation: the spec
// requires ports in the decimal range 0..65535, and a hand-built header must
// not serialize values outside it.
func TestFormatV1InvalidPorts(t *testing.T) {
	for _, port := range []int{-1, 65536, 700000} {
		header := &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        &net.TCPAddr{IP: net.ParseIP("10.1.1.1"), Port: port},
			DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("20.2.2.2"), Port: 443},
		}
		if _, err := header.Format(); !errors.Is(err, ErrInvalidPortNumber) {
			t.Fatalf("port %d: expected ErrInvalidPortNumber, got %v", port, err)
		}
	}
}

func TestReadV1Invalid(t *testing.T) {
	for _, tt := range invalidParseV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, err := Read(tt.reader); !errors.Is(err, tt.expectedError) {
				t.Fatalf("expected %s, actual %v", tt.expectedError, err)
			}
		})
	}
}

var validParseAndWriteV1Tests = []struct {
	desc           string
	reader         *bufio.Reader
	expectedHeader *Header
	// expectedWrite is the exact wire output formatVersion1 must produce for
	// expectedHeader. It is asserted byte-for-byte by TestWriteV1Valid, which a
	// round-trip + EqualsTo check cannot do: EqualsTo compares net.IP.String(),
	// so a v4-mapped IPv6 ("::ffff:1.2.3.4") and its collapsed v4 form ("1.2.3.4")
	// look equal there, hiding serialization regressions.
	expectedWrite string
}{
	{
		desc:   "TCP4",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP4V1)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv4,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
		},
		expectedWrite: "PROXY TCP4 127.0.0.1 127.0.0.1 65533 65533" + crlf,
	},
	{
		desc:   "TCP6",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP6V1)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v6addr,
			DestinationAddr:   v6addr,
		},
		expectedWrite: "PROXY TCP6 ::1 ::1 65533 65533" + crlf,
	},
	{
		desc:   "TCP4IN6",
		reader: bufio.NewReader(strings.NewReader(fixtureTCP4IN6V1)),
		expectedHeader: &Header{
			Version:           1,
			Command:           PROXY,
			TransportProtocol: TCPv6,
			SourceAddr:        v4addr,
			DestinationAddr:   v4addr,
		},
		// Regression lock for the netip.Addr fix: a v4 IP carried in a TCP6 header
		// must serialize as ::ffff:127.0.0.1, not the collapsed 127.0.0.1 that
		// net.IP.String() used to emit (which produced an invalid v4-in-TCP6 line).
		expectedWrite: "PROXY TCP6 ::ffff:127.0.0.1 ::ffff:127.0.0.1 65533 65533" + crlf,
	},
	{
		desc:   "unknown",
		reader: bufio.NewReader(strings.NewReader(fixtureUnknown)),
		expectedHeader: &Header{
			Version:           1,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
		},
		expectedWrite: "PROXY UNKNOWN" + crlf,
	},
	{
		desc:   "unknown with addresses and ports",
		reader: bufio.NewReader(strings.NewReader(fixtureUnknownWithAddresses)),
		expectedHeader: &Header{
			Version:           1,
			Command:           LOCAL,
			TransportProtocol: UNSPEC,
			SourceAddr:        nil,
			DestinationAddr:   nil,
		},
		// UNSPEC always serializes to the short form; addresses are dropped.
		expectedWrite: "PROXY UNKNOWN" + crlf,
	},
	// NOTE: plain IPv4 literals in TCP6 lines (nginx OSS compatibility) are
	// covered by TestParseV1IPv4InTCP6Compat; by default they are rejected.
}

func TestParseV1Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			header, err := Read(tt.reader)
			if err != nil {
				t.Fatal("unexpected error", err.Error())
			}
			if !header.EqualsTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, header)
			}
		})
	}
}

func TestWriteV1Valid(t *testing.T) {
	for _, tt := range validParseAndWriteV1Tests {
		t.Run(tt.desc, func(t *testing.T) {
			var b bytes.Buffer
			w := bufio.NewWriter(&b)
			if _, err := tt.expectedHeader.WriteTo(w); err != nil {
				t.Fatal("unexpected error ", err)
			}
			if err := w.Flush(); err != nil {
				t.Fatal("unexpected error ", err)
			}

			// Assert the exact wire bytes. This is what pins address-family
			// formatting (e.g. v4-mapped IPv6 rendering as ::ffff:x.x.x.x); the
			// EqualsTo round-trip below is blind to it because it compares
			// net.IP.String(), which collapses ::ffff:x.x.x.x back to x.x.x.x.
			if got := b.String(); got != tt.expectedWrite {
				t.Fatalf("expected wire %q, actual %q", tt.expectedWrite, got)
			}

			// Round-trip the written bytes to ensure the parser accepts what the
			// formatter emits (catches format/parse drift that a byte check alone
			// would miss).
			r := bufio.NewReader(&b)
			newHeader, err := Read(r)
			if err != nil {
				t.Fatal("unexpected error ", err)
			}

			if !newHeader.EqualsTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, newHeader)
			}
		})
	}
}

// Tests for parseVersion1 overflow - issue #69.

type dataSource struct {
	NBytes int
	NRead  int
}

func (ds *dataSource) Read(b []byte) (int, error) {
	if ds.NRead >= ds.NBytes {
		return 0, io.EOF
	}
	avail := ds.NBytes - ds.NRead
	avail = min(avail, len(b))
	for i := 0; i < avail; i++ {
		b[i] = 0x20
	}
	ds.NRead += avail
	return avail, nil
}

func TestParseVersion1Overflow(t *testing.T) {
	ds := &dataSource{}
	reader := bufio.NewReader(ds)
	bufSize := reader.Size()
	ds.NBytes = bufSize * 16
	_, _ = parseVersion1(reader)
	if ds.NRead > bufSize {
		t.Fatalf("read: expected max %d bytes, actual %d\n", bufSize, ds.NRead)
	}
}

// listen binds a localhost TCP listener wrapped in a Listener. When
// readHeaderTimeout > 0 the Listener is given that header timeout, which lets
// tests pin the deadline-bound (rather than single-read) behavior without
// waiting for DefaultReadHeaderTimeout.
func listen(t *testing.T, readHeaderTimeout ...time.Duration) *Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	pl := &Listener{Listener: l}
	if len(readHeaderTimeout) > 0 {
		pl.ReadHeaderTimeout = readHeaderTimeout[0]
	}
	return pl
}

func client(t *testing.T, addr, header string, length int, terminate bool, wait time.Duration, done chan struct{},
	result chan error,
) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		result <- fmt.Errorf("dial: %w", err)
		return
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("failed to close connection: %v", err)
		}
	})

	if terminate && length < 2 {
		length = 2
	}

	buf := make([]byte, len(header)+length)
	copy(buf, []byte(header))
	for i := 0; i < length-2; i++ {
		buf[i+len(header)] = 0x20
	}
	if terminate {
		copy(buf[len(header)+length-2:], []byte(crlf))
	}

	n, err := c.Write(buf)
	if err != nil {
		result <- fmt.Errorf("write: %w", err)
		return
	}
	if n != len(buf) {
		result <- errors.New("write; short write")
		return
	}

	close(result)
	time.Sleep(wait)
	close(done)
}

func TestVersion1Overflow(t *testing.T) {
	done := make(chan struct{})
	cliResult := make(chan error)

	l := listen(t)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 10240, true, 10*time.Second, done, cliResult)

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	b := []byte{}
	_, err = c.Read(b)
	if !errors.Is(err, ErrVersion1HeaderTooLong) {
		t.Fatalf("net.Conn: expected ErrVersion1HeaderTooLong for oversized header, got %v", err)
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

// TestVersion1SlowLoris pins the deadline bound that replaces the old
// single-read abort: a partial v1 line without a terminating CRLF no longer
// fails because it spanned multiple reads, but a client that stalls before the
// CRLF must still be released when the header-read timeout fires. The timeout
// surfaces as ErrNoProxyProtocol (a timing outcome), not as a v1 format error.
func TestVersion1SlowLoris(t *testing.T) {
	const headerTimeout = 100 * time.Millisecond

	done := make(chan struct{})
	cliResult := make(chan error)
	timeout := make(chan error)

	l := listen(t, headerTimeout)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 0, false, time.Second, done, cliResult)

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	go func() {
		b := []byte{}
		_, err = c.Read(b)
		timeout <- err
	}()

	select {
	case <-done:
		t.Fatalf("net.Conn: reader still blocked after the client gave up")
	case err := <-timeout:
		if !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol for a stalled partial header, got %v", err)
		}
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

// TestVersion1SlowLorisOverflow combines both bounds: a stalled, delimiter-free
// line that also exceeds the 107-byte limit is rejected promptly — either by
// ErrVersion1HeaderTooLong once the limit is reached, or by the header timeout
// if the bytes themselves arrive too slowly. Both outcomes are stable rejects
// that release the goroutine instead of blocking on the client.
func TestVersion1SlowLorisOverflow(t *testing.T) {
	const headerTimeout = 500 * time.Millisecond

	done := make(chan struct{})
	cliResult := make(chan error)
	timeout := make(chan error)

	l := listen(t, headerTimeout)
	go client(t, l.Addr().String(), fixtureTCP6V1Overflow, 10240, false, 2*time.Second, done, cliResult)

	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	go func() {
		b := []byte{}
		_, err = c.Read(b)
		timeout <- err
	}()

	select {
	case <-done:
		t.Fatalf("net.Conn: reader still blocked after the client gave up")
	case err := <-timeout:
		if err == nil {
			t.Fatalf("net.Conn: no error reported for incomplete and overflowed header")
		}
		if !errors.Is(err, ErrVersion1HeaderTooLong) && !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected header-too-long or timeout, got %v", err)
		}
	}
	err = <-cliResult
	if err != nil {
		t.Fatalf("client error: %v", err)
	}
}

// TestParseV1Boundaries pins the spec's numeric edges exactly: port 65535 is
// the last valid port and 65536 the first invalid one; 107 bytes (including
// CRLF) is the longest valid line and 108 the shortest invalid one.
func TestParseV1Boundaries(t *testing.T) {
	t.Run("port 65535 accepted", func(t *testing.T) {
		h, err := Read(newBufioReader([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 65535 65535" + crlf)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if src, dst, ok := h.Ports(); !ok || src != 65535 || dst != 65535 {
			t.Fatalf("expected ports 65535/65535, got %d/%d ok=%v", src, dst, ok)
		}
	})
	t.Run("port 65536 rejected", func(t *testing.T) {
		if _, err := Read(newBufioReader([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 65536 443" + crlf))); !errors.Is(err, ErrInvalidPortNumber) {
			t.Fatalf("expected ErrInvalidPortNumber, got %v", err)
		}
	})

	// "PROXY UNKNOWN" plus filler up to the limit; the receiver must ignore
	// everything before the CRLF.
	line107 := "PROXY UNKNOWN " + strings.Repeat("x", 107-len("PROXY UNKNOWN ")-len(crlf)) + crlf
	if len(line107) != 107 {
		t.Fatalf("fixture error: line is %d bytes, want 107", len(line107))
	}
	t.Run("107-byte line accepted", func(t *testing.T) {
		h, err := Read(newBufioReader([]byte(line107)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !h.Command.IsLocal() {
			t.Fatalf("expected UNKNOWN to map to LOCAL, got %#x", byte(h.Command))
		}
	})
	t.Run("108-byte line rejected", func(t *testing.T) {
		line108 := "PROXY UNKNOWN " + strings.Repeat("x", 108-len("PROXY UNKNOWN ")-len(crlf)) + crlf
		if _, err := Read(newBufioReader([]byte(line108))); !errors.Is(err, ErrVersion1HeaderTooLong) {
			t.Fatalf("expected ErrVersion1HeaderTooLong, got %v", err)
		}
	})
}

// chunkedReader feeds its data one chunk of at most maxChunk bytes per Read,
// simulating a TCP stack that delivers the v1 line in arbitrarily small
// segments.
type chunkedReader struct {
	data     []byte
	pos      int
	maxChunk int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := min(r.maxChunk, min(len(p), len(r.data)-r.pos))
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}

// headerReadTimeout is the net.Error returned when a read deadline fires.
type headerReadTimeout struct{}

func (headerReadTimeout) Error() string   { return "i/o timeout" }
func (headerReadTimeout) Timeout() bool   { return true }
func (headerReadTimeout) Temporary() bool { return true }

// prefixTimeoutReader hands out its prefix once, then blocks with a read
// timeout on every subsequent Read, modeling a slow client that stalls in the
// middle of the v1 line before the CRLF.
type prefixTimeoutReader struct {
	prefix []byte
	pos    int
}

func (r *prefixTimeoutReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.prefix) {
		return 0, headerReadTimeout{}
	}
	n := copy(p, r.prefix[r.pos:])
	r.pos += n
	return n, nil
}

// TestParseV1ArbitraryFragmentation pins requirement 1 at the parser level:
// the line may arrive in segments of any size (down to one byte per read), and
// application bytes that arrive with the final segment must stay buffered past
// the parsed header instead of being swallowed.
func TestParseV1ArbitraryFragmentation(t *testing.T) {
	lines := []string{fixtureTCP4V1, fixtureTCP6V1, fixtureUnknown, fixtureUnknownWithAddresses}
	for _, line := range lines {
		t.Run(fmt.Sprintf("line=%dbytes", len(line)), func(t *testing.T) {
			for chunkSize := 1; chunkSize <= 5; chunkSize++ {
				t.Run(fmt.Sprintf("chunksize=%d", chunkSize), func(t *testing.T) {
					// A deliberately tiny buffer so bufio itself also has to
					// refill; chunkedReader then limits each refill further.
					reader := bufio.NewReaderSize(&chunkedReader{data: []byte(line), maxChunk: chunkSize}, 16)
					header, err := Read(reader)
					if err != nil {
						t.Fatalf("Read failed: %v", err)
					}
					if header.Version != 1 {
						t.Fatalf("expected a v1 header, got version %d", header.Version)
					}
					// The trailing "GET /" in the TCP4/TCP6 fixtures is application
					// data and must remain readable; the other fixtures have none.
					if rest := line[strings.Index(line, crlf)+len(crlf):]; rest != "" {
						got, err := io.ReadAll(reader)
						if err != nil {
							t.Fatalf("reading buffered payload: %v", err)
						}
						if string(got) != rest {
							t.Fatalf("payload not preserved: got %q, want %q (full line %q)", got, rest, line)
						}
					}
				})
			}
		})
	}
}

// TestParseV1TimeoutIsNotFormatError pins requirement 3 at the parser level:
// when the read deadline fires while a partial line is buffered, the timeout
// comes back as a net.Error rather than as a v1 parse/format error, so the
// caller can tell "timed out" apart from "rejected".
func TestParseV1TimeoutIsNotFormatError(t *testing.T) {
	reader := bufio.NewReader(&prefixTimeoutReader{prefix: []byte("PROXY TCP4 1.2.3.4 5.6.7.8 80")})

	_, err := Read(reader)
	if err == nil {
		t.Fatal("expected an error when the deadline fires mid-header")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a net.Error timeout, got %v (%T)", err, err)
	}
	if errors.Is(err, ErrCantReadVersion1Header) ||
		errors.Is(err, ErrVersion1HeaderTooLong) ||
		errors.Is(err, ErrLineMustEndWithCrlf) ||
		errors.Is(err, ErrCantReadAddressFamilyAndProtocol) ||
		errors.Is(err, ErrInvalidAddress) ||
		errors.Is(err, ErrInvalidPortNumber) {
		t.Fatalf("a timeout must not be classified as a v1 format error, got %v", err)
	}
}

// TestParseV1TruncatedLineIsReadError pins that a clean EOF before the
// terminating CRLF is a read/format failure (retry cannot complete the line on
// a half-closed connection), not a timeout.
func TestParseV1TruncatedLineIsReadError(t *testing.T) {
	reader := newBufioReader([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443"))
	_, err := Read(reader)
	if !errors.Is(err, ErrCantReadVersion1Header) {
		t.Fatalf("expected ErrCantReadVersion1Header for an EOF-truncated line, got %v", err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("EOF truncation must not classify as a timeout, got %v", err)
	}
}

// TestParseV1UnknownProtocolKeepsRawToken pins requirement 4: an unrecognized
// transport-protocol token is rejected without fabricating any connection
// address, while the raw token is preserved in the error for diagnostics.
func TestParseV1UnknownProtocolKeepsRawToken(t *testing.T) {
	const raw = "PROXY FOO 1.2.3.4 5.6.7.8 80 443" + crlf
	header, err := Read(newBufioReader([]byte(raw)))
	if !errors.Is(err, ErrCantReadAddressFamilyAndProtocol) {
		t.Fatalf("expected ErrCantReadAddressFamilyAndProtocol, got %v", err)
	}
	if !strings.Contains(err.Error(), `"FOO"`) {
		t.Fatalf("expected the raw token %q to be retained in the error, got %v", "FOO", err)
	}
	if header != nil {
		t.Fatalf("no header may be produced for an unknown protocol, got %+v", header)
	}
}

// TestParseV1RejectedHeaderBytesNotTreatedAsPayload pins requirement 5 at the
// reader level: bytes of a rejected line that had not yet been consumed stay
// in the bufio.Reader as stream bytes — they are never reinterpreted as a
// parsed header's addresses — and a payload trailing the line remains
// reachable rather than being merged into a header.
func TestParseV1RejectedHeaderBytesNotTreatedAsPayload(t *testing.T) {
	for _, tc := range []struct {
		desc        string
		wire        string
		expectedErr error
	}{
		{
			desc:        "bare LF instead of CRLF",
			wire:        "PROXY TCP4 1.2.3.4 5.6.7.8 80 443\nGET /",
			expectedErr: ErrLineMustEndWithCrlf,
		},
		{
			desc:        "unknown transport token",
			wire:        "PROXY FOO 1.2.3.4 5.6.7.8 80 443" + crlf + "GET /",
			expectedErr: ErrCantReadAddressFamilyAndProtocol,
		},
		{
			desc:        "invalid port",
			wire:        "PROXY TCP4 1.2.3.4 5.6.7.8 notaport 443" + crlf + "GET /",
			expectedErr: ErrInvalidPortNumber,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			reader := newBufioReader([]byte(tc.wire))
			header, err := Read(reader)
			if !errors.Is(err, tc.expectedErr) {
				t.Fatalf("expected %v, got %v", tc.expectedErr, err)
			}
			if header != nil {
				t.Fatalf("rejected line must not yield a header, got %+v", header)
			}
			// The trailing application bytes must still be ordinary stream bytes
			// and must never have been turned into proxy addresses.
			rest, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("reading remaining stream bytes: %v", err)
			}
			if !strings.HasSuffix(string(rest), "GET /") {
				t.Fatalf("payload not retained as plain stream data: got %q", string(rest))
			}
		})
	}
}

// TestParseV1TooLongHeaderKeepsTrailingPayload exercises the 107-byte bound
// with a payload in the same stream: the line is rejected deterministically
// (never parsed), and the payload stays buffered rather than being consumed as
// part of the header.
func TestParseV1TooLongHeaderKeepsTrailingPayload(t *testing.T) {
	line := "PROXY UNKNOWN " + strings.Repeat("x", maxV1HeaderSize-len("PROXY UNKNOWN ")) // exactly 107 bytes, no CRLF
	if len(line) != maxV1HeaderSize {
		t.Fatalf("fixture error: line is %d bytes, want %d", len(line), maxV1HeaderSize)
	}
	reader := newBufioReader([]byte(line + "GET /"))
	header, err := Read(reader)
	if !errors.Is(err, ErrVersion1HeaderTooLong) {
		t.Fatalf("expected ErrVersion1HeaderTooLong, got %v", err)
	}
	if header != nil {
		t.Fatalf("oversized line must not yield a header, got %+v", header)
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading remaining stream bytes: %v", err)
	}
	if string(rest) != "GET /" {
		t.Fatalf("payload must stay buffered after an over-long header, got %q", string(rest))
	}
}
