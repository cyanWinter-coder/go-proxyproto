package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrDatagramTruncated indicates that a datagram began with a PROXY protocol
// signature but ended before the header it declares was complete.
//
// A datagram is self-contained: unlike a stream, bytes for the missing part of
// the header can never arrive later, and the next datagram is a different
// message, not a continuation. Receivers must drop the datagram and continue
// with the next one; ParseUDPDatagram and UDPPacketConn therefore never read
// ahead to complete a header.
//
// It is deliberately distinct from ErrNoProxyProtocol (no header was present)
// and from ErrInvalidLength (a complete header declared an invalid length), so
// a receiver can count drops per cause. The returned error also wraps
// io.ErrUnexpectedEOF, matching what a short stream header reports.
var ErrDatagramTruncated = errors.New("proxyproto: proxy protocol header extends past the end of the datagram")

// ParseUDPDatagram parses a PROXY protocol header at the start of a UDP
// datagram and returns the header together with the proxied payload that
// follows it. The returned payload aliases the datagram slice.
//
// Per spec (section 2), when the PROXY protocol is carried over UDP the header
// and the proxied payload MUST be sent in the same datagram, and the receiver
// MUST parse the header independently for each received datagram. Call this
// for every datagram received; there is no connection state to carry over.
// Conn and Listener are stream-oriented and cannot provide those semantics.
//
// Parsing is confined to the datagram passed in: the header is delimited by its
// own declared length (v2) or CRLF (v1), and the payload starts exactly where
// the header ends. Bytes outside the datagram can never be consulted, so a
// header cannot be completed from, or accidentally consume, the next datagram.
//
// A datagram that does not begin with a header fails with ErrNoProxyProtocol
// when the signature is absent. A datagram whose signature is present but
// which ends before the declared header does fails with ErrDatagramTruncated.
// Both are drop conditions: the spec forbids guessing whether a header is
// present, so on a receiver configured for the PROXY protocol such datagrams
// must not be treated as raw payload.
//
// On success the payload is exactly the bytes following the header; it is
// empty (but non-nil when the datagram is non-nil) when the datagram carries
// no proxied payload.
func ParseUDPDatagram(datagram []byte) (*Header, []byte, error) {
	headerLen, err := udpHeaderLen(datagram)
	if err != nil {
		return nil, nil, err
	}

	// Delimit the reader to the header only. The parser cannot observe payload
	// bytes, let alone another datagram, so a header can neither borrow bytes
	// from nor consume the proxied payload.
	byteReader := bytes.NewReader(datagram[:headerLen])
	// Size the buffer to the header so it is fully buffered up front: v1
	// parsing requires the line to be available without a refill (slow-loris
	// defense), and v2 parsing needs the announced bytes.
	reader := bufio.NewReaderSize(byteReader, headerLen)
	header, err := Read(reader)
	if err != nil {
		return nil, nil, err
	}

	return header, datagram[headerLen:], nil
}

// udpHeaderLen returns the exact length of the PROXY protocol header at the
// start of datagram. It validates that the header is complete within the
// datagram before any parsing happens, so a truncated or over-declared header
// is reported as such instead of surfacing as a generic read error.
func udpHeaderLen(datagram []byte) (int, error) {
	switch {
	case bytes.HasPrefix(datagram, SIGV2):
		// Fixed prefix: signature (12) + version/command (1) + family (1) +
		// declared length (2). The declared length covers the address block
		// and any TLVs, but not these 16 bytes.
		const fixedV2Len = 16
		if len(datagram) < fixedV2Len {
			// The signature matched but the fixed prefix is incomplete, so the
			// declared length cannot even be read: the header is cut short.
			return 0, fmt.Errorf("%w: v2 fixed prefix needs %d bytes, datagram has %d: %w",
				ErrDatagramTruncated, fixedV2Len, len(datagram), io.ErrUnexpectedEOF)
		}
		length := int(binary.BigEndian.Uint16(datagram[14:16]))
		available := len(datagram) - fixedV2Len
		overCap := length > int(MaxV2HeaderSize)

		// The declared bytes must all be present in this datagram: the missing
		// part can never arrive later, and the next datagram is a different
		// message, not a continuation. This takes precedence over the size cap
		// because it describes what actually happened to this datagram; when the
		// declaration also exceeds the cap, both causes are reported.
		if length > available {
			if overCap {
				return 0, fmt.Errorf("%w: %w: v2 header declares %d bytes after the fixed prefix, exceeding MaxV2HeaderSize=%d, and this datagram carries %d: %w",
					ErrDatagramTruncated, ErrInvalidLength, length, MaxV2HeaderSize, available, io.ErrUnexpectedEOF)
			}
			return 0, fmt.Errorf("%w: v2 header declares %d bytes after the fixed prefix, datagram carries %d: %w",
				ErrDatagramTruncated, length, available, io.ErrUnexpectedEOF)
		}
		if overCap {
			return 0, ErrInvalidLength
		}
		return fixedV2Len + length, nil

	case bytes.HasPrefix(datagram, SIGV1):
		// A v1 line is terminated by LF; parseVersion1 additionally requires
		// the preceding byte to be CR and caps the line at 107 bytes.
		lineEnd := bytes.IndexByte(datagram, '\n')
		if lineEnd < 0 {
			if len(datagram) >= 107 {
				return 0, ErrVersion1HeaderTooLong
			}
			return 0, fmt.Errorf("%w: v1 header is not terminated by CRLF, datagram has %d bytes: %w",
				ErrDatagramTruncated, len(datagram), io.ErrUnexpectedEOF)
		}
		if lineEnd >= 107 {
			return 0, ErrVersion1HeaderTooLong
		}
		return lineEnd + 1, nil
	}

	// A non-empty proper prefix of a signature can never become a header: no
	// later bytes can arrive in this datagram. Reporting it as a truncation
	// rather than "no header" tells an operator that the peer started speaking
	// the protocol and the datagram was cut short.
	if len(datagram) > 0 && len(datagram) < len(SIGV2) && bytes.HasPrefix(SIGV2, datagram) {
		return 0, fmt.Errorf("%w: v2 signature cut off after %d bytes: %w", ErrDatagramTruncated, len(datagram), io.ErrUnexpectedEOF)
	}
	if len(datagram) > 0 && len(datagram) < len(SIGV1) && bytes.HasPrefix(SIGV1, datagram) {
		return 0, fmt.Errorf("%w: v1 signature cut off after %d bytes: %w", ErrDatagramTruncated, len(datagram), io.ErrUnexpectedEOF)
	}

	// Anything else has no header at all.
	return 0, ErrNoProxyProtocol
}

// FormatUDPDatagram renders the header followed by the proxied payload,
// producing the exact bytes to send as one UDP datagram. Per spec (section 2)
// the header and the payload MUST share a single datagram, which a single
// write of the returned slice guarantees; formatting the header and payload
// separately risks a sender splitting them across datagrams.
//
// The payload is copied, so later changes to it do not alter the returned
// datagram. An empty payload yields the header bytes alone.
func (header *Header) FormatUDPDatagram(payload []byte) ([]byte, error) {
	buf, err := header.Format()
	if err != nil {
		return nil, err
	}
	// Append into a fresh slice rather than reusing buf's capacity: Format may
	// return a subslice of a larger backing array, and growing it in place
	// would clobber that array for other holders of buf.
	out := make([]byte, 0, len(buf)+len(payload))
	out = append(out, buf...)
	return append(out, payload...), nil
}
