package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	crlf      = "\r\n"
	separator = " "

	// maxV1HeaderSize is the maximum length of a v1 header line including the
	// terminating CRLF. Per the spec, the worst case is:
	//
	//	"PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
	//	=> 5 + 1 + 7 + 1 + 39 + 1 + 39 + 1 + 5 + 1 + 5 + 2 = 107 chars
	//
	// A 108-byte buffer would therefore always hold a whole line, and a line
	// whose 108th byte is not a LF is rejected with ErrVersion1HeaderTooLong.
	maxV1HeaderSize = 107

	// v1ProtoTCP4 and v1ProtoTCP6 are the PROXY protocol v1 transport-protocol
	// tokens for TCP over IPv4 and IPv6 respectively (net has no constants for
	// these textual identifiers).
	v1ProtoTCP4 = "TCP4"
	v1ProtoTCP6 = "TCP6"
)

// V1AcceptIPv4InTCP6 permits plain IPv4 literals in the address fields of a v1
// TCP6 line, promoting them to v4-mapped IPv6 (::ffff:x.x.x.x). Some proxies
// (notably the nginx OSS stream module) emit such lines when the client and
// backend address families differ. The spec forbids them — "the advertised
// protocol family dictates what format to use" — so this compatibility mode is
// disabled by default.
//
// Note the promotion is lossy: round-trip serialization renders the address as
// "::ffff:x.x.x.x" rather than the original "x.x.x.x".
//
// Like DefaultReadHeaderTimeout, this is a package-level variable to keep it
// easy to override. Set it at program init; it must not be modified
// concurrently with parsing.
var V1AcceptIPv4InTCP6 = false

func initVersion1() *Header {
	header := new(Header)
	header.Version = 1
	// Command doesn't exist in v1
	header.Command = PROXY
	return header
}

// readByteOrHeaderTimeout performs a bufio.Reader.ReadByte that keeps a read
// deadline firing distinguishable from a malformed header: a net.Error timeout
// (or any net.Error implementing Timeout()) is returned unwrapped, while every
// other read failure — clean EOF on a truncated line included — is wrapped
// with formatErr. v1 and v2 share it so both parsers give callers the same
// "timed out vs. rejected" classification (errors.As works on the result
// either way).
func readByteOrHeaderTimeout(reader *bufio.Reader, formatErr error) (byte, error) {
	b, err := reader.ReadByte()
	if err != nil {
		return 0, wrapHeaderReadError(formatErr, err)
	}
	return b, nil
}

// wrapHeaderReadError keeps a read-deadline failure distinguishable from a
// malformed header: a net.Error timeout is returned unwrapped, while every
// other read failure (clean EOF on a truncated frame included) is wrapped with
// formatErr. Both v1 and v2 route their read failures through it so callers
// get one classification rule, and errors.As still finds the underlying cause
// of a wrapped failure.
func wrapHeaderReadError(formatErr, err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return err
	}
	return fmt.Errorf("%w: %w", formatErr, err)
}

func parseVersion1(reader *bufio.Reader) (*Header, error) {
	// The spec derives the 107-byte line limit (see maxV1HeaderSize) and mandates
	// CRLF termination; the header never otherwise contains a CR or LF byte.
	//
	// Edge connections frequently deliver the line split across arbitrarily
	// small TCP segments, and a slow client may pause before the CRLF, so the
	// read loop is tolerant of partial lines instead of requiring the line to
	// arrive from a single underlying read. Three independent bounds make that
	// tolerance safe against stalled or abusive peers:
	//
	//   - the first LF byte ends the line (and must be preceded by CR);
	//   - maxV1HeaderSize caps how many bytes may belong to the line, so a peer
	//     sending delimiter-free data is rejected with ErrVersion1HeaderTooLong;
	//   - the caller's read deadline bounds how long a stalled peer can hold the
	//     loop. A deadline firing is not a format error: the net.Error timeout is
	//     returned unwrapped so errors.As(err, new(net.Error)) distinguishes it
	//     from a genuinely malformed header, leaving the caller free to retry or
	//     drop the connection.
	//
	// Only bytes consumed while looking for the LF leave the reader. Any payload
	// that arrived in the same TCP segment(s) as the line stays buffered, so a
	// well-formed header never swallows the application's first packet. A
	// malformed header, on the other hand, is rejected outright: its bytes are
	// never reinterpreted as application data (Conn caches the error and every
	// subsequent Read fails the same way).
	buf := make([]byte, 0, maxV1HeaderSize)
	for {
		b, err := readByteOrHeaderTimeout(reader, ErrCantReadVersion1Header)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b)
		if b == '\n' {
			// End of header found
			break
		}
		if len(buf) == maxV1HeaderSize {
			// No delimiter within the maximum header length.
			return nil, ErrVersion1HeaderTooLong
		}
	}

	// Check for CR before LF.
	if len(buf) < 2 || buf[len(buf)-2] != '\r' {
		return nil, ErrLineMustEndWithCrlf
	}

	// Check full signature. Read dispatches to this parser after peeking only
	// the first 5 bytes ("PROXY"), so the first token must still be checked to
	// be exactly "PROXY": per spec the line starts with "PROXY" followed by
	// exactly one space, and anything else (e.g. "PROXYjunk TCP4 ...") is not a
	// v1 header.
	tokens := strings.Split(string(buf[:len(buf)-2]), separator)
	if tokens[0] != "PROXY" {
		return nil, ErrCantReadVersion1Header
	}

	// Expect at least 2 tokens: "PROXY" and the transport protocol.
	if len(tokens) < 2 {
		return nil, ErrCantReadAddressFamilyAndProtocol
	}

	// Read address family and protocol
	var transportProtocol AddressFamilyAndProtocol
	switch tokens[1] {
	case v1ProtoTCP4:
		transportProtocol = TCPv4
	case v1ProtoTCP6:
		transportProtocol = TCPv6
	case "UNKNOWN":
		transportProtocol = UNSPEC // doesn't exist in v1 but fits UNKNOWN
	default:
		// Reject rather than guess: the token names no supported family, so no
		// SourceAddr/DestinationAddr may be fabricated. Keep the raw token in the
		// error so the sender's original declaration is not lost to the receiver.
		return nil, fmt.Errorf("%w: %q", ErrCantReadAddressFamilyAndProtocol, tokens[1])
	}

	// Expect exactly 6 tokens when UNKNOWN is not present. The spec's TCP4/TCP6
	// line is "PROXY <proto> <src> <dst> <sport> <dport>"; trailing tokens are
	// not permitted. (UNKNOWN is handled leniently below, per spec: the receiver
	// must ignore anything up to the CRLF.)
	if transportProtocol != UNSPEC && len(tokens) != 6 {
		return nil, ErrCantReadAddressFamilyAndProtocol
	}

	// When a signature is found, allocate a v1 header with Command set to PROXY.
	// Command doesn't exist in v1 but set it for other parts of this library
	// to rely on it for determining connection details.
	header := initVersion1()

	// Transport protocol has been processed already.
	header.TransportProtocol = transportProtocol

	// When UNKNOWN, set the command to LOCAL and return early
	if header.TransportProtocol == UNSPEC {
		header.Command = LOCAL
		return header, nil
	}

	// Otherwise, continue to read addresses and ports
	sourceIP, err := parseV1IPAddress(header.TransportProtocol, tokens[2])
	if err != nil {
		return nil, err
	}
	destIP, err := parseV1IPAddress(header.TransportProtocol, tokens[3])
	if err != nil {
		return nil, err
	}
	sourcePort, err := parseV1PortNumber(tokens[4])
	if err != nil {
		return nil, err
	}
	destPort, err := parseV1PortNumber(tokens[5])
	if err != nil {
		return nil, err
	}
	header.SourceAddr = &net.TCPAddr{
		IP:   sourceIP,
		Port: sourcePort,
	}
	header.DestinationAddr = &net.TCPAddr{
		IP:   destIP,
		Port: destPort,
	}

	return header, nil
}

func (header *Header) formatVersion1() ([]byte, error) {
	// As of version 1, only "TCP4" ( \x54 \x43 \x50 \x34 ) for TCP over IPv4,
	// and "TCP6" ( \x54 \x43 \x50 \x36 ) for TCP over IPv6 are allowed.
	var proto string
	switch header.TransportProtocol {
	case TCPv4:
		proto = v1ProtoTCP4
	case TCPv6:
		proto = v1ProtoTCP6
	default:
		// Unknown connection (short form)
		return []byte("PROXY UNKNOWN" + crlf), nil
	}

	sourceAddr, sourceOK := header.SourceAddr.(*net.TCPAddr)
	destAddr, destOK := header.DestinationAddr.(*net.TCPAddr)
	if !sourceOK || !destOK {
		return nil, ErrInvalidAddress
	}

	// A hand-built header can carry any int; the spec requires ports in the
	// decimal range 0..65535, so validate before serializing (mirrors the v2
	// port check in formatVersion2).
	if sourceAddr.Port < 0 || sourceAddr.Port > math.MaxUint16 || destAddr.Port < 0 || destAddr.Port > math.MaxUint16 {
		return nil, ErrInvalidPortNumber
	}

	// netip.Addr (not net.IP) is used here so String() honors the address family
	// declared by TransportProtocol. AddrFromSlice reports ok=false when the slice
	// is nil (e.g. To4() on an IPv6-only address), which the guard below rejects.
	var sourceIP, destIP netip.Addr
	switch header.TransportProtocol {
	case TCPv4:
		sourceIP, sourceOK = netip.AddrFromSlice(sourceAddr.IP.To4())
		destIP, destOK = netip.AddrFromSlice(destAddr.IP.To4())
	case TCPv6:
		// Use netip.Addr instead of net.IP to guarantee an Is6() address; i.e. a
		// v4-mapped IP in a TCP6 header serializes as ::ffff:1.2.3.4 instead of
		// net.IP.String()'s collapsed 1.2.3.4.
		sourceIP, sourceOK = netip.AddrFromSlice(sourceAddr.IP.To16())
		destIP, destOK = netip.AddrFromSlice(destAddr.IP.To16())
	default:
		// Unreachable today: the proto switch at the top of this function already
		// returns for anything other than TCPv4/TCPv6. Kept so a future protocol
		// can't fall through with zero-value IPs while sourceOK/destOK still hold
		// from the type assertion above.
		return nil, ErrInvalidAddress
	}
	if !sourceOK || !destOK {
		return nil, ErrInvalidAddress
	}

	buf := bytes.NewBuffer(make([]byte, 0, 108))
	buf.Write(SIGV1)
	buf.WriteString(separator)
	buf.WriteString(proto)
	buf.WriteString(separator)
	buf.WriteString(sourceIP.String())
	buf.WriteString(separator)
	buf.WriteString(destIP.String())
	buf.WriteString(separator)
	buf.WriteString(strconv.Itoa(sourceAddr.Port))
	buf.WriteString(separator)
	buf.WriteString(strconv.Itoa(destAddr.Port))
	buf.WriteString(crlf)

	return buf.Bytes(), nil
}

func parseV1PortNumber(portStr string) (int, error) {
	// Per spec, a v1 port is 1..5 decimal digits in the range 0..65535, with no
	// leading zero and no sign. ParseUint with bitSize 16 enforces all of that
	// (it rejects empty strings, signs, non-digits, and values above 65535)
	// except the leading zero ("080"), which the spec forbids and which creates
	// ambiguity for anything downstream that re-parses the address.
	if len(portStr) > 1 && portStr[0] == '0' {
		return 0, ErrInvalidPortNumber
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidPortNumber, err)
	}
	return int(port), nil
}

func parseV1IPAddress(protocol AddressFamilyAndProtocol, addrStr string) (net.IP, error) {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAddress, err)
	}
	// netip accepts zoned literals ("fe80::1%eth0"). The spec's address grammar
	// does not (hex digits and colons only), and net.IP cannot carry a zone, so
	// accepting one would silently forward an address the sender never wrote.
	// Per spec, "any sequence which does not exactly match the protocol must be
	// discarded".
	if addr.Zone() != "" {
		return nil, ErrInvalidAddress
	}

	switch protocol {
	case TCPv4:
		if addr.Is4() {
			return net.IP(addr.AsSlice()), nil
		}
	case TCPv6:
		if addr.Is6() || addr.Is4In6() {
			return net.IP(addr.AsSlice()), nil
		}
		// Plain IPv4 in a TCP6 line is spec-invalid but emitted by some proxies;
		// see V1AcceptIPv4InTCP6 for the compatibility trade-off.
		if V1AcceptIPv4InTCP6 && addr.Is4() {
			mapped := netip.AddrFrom16(addr.As16())
			return net.IP(mapped.AsSlice()), nil
		}
	}

	return nil, ErrInvalidAddress
}
