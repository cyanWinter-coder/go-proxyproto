package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
)

// TestParseUDPDatagram pins the spec's UDP mode (section 2): the header and
// the proxied payload share one datagram, and each datagram is parsed
// independently. Positive cases return the header and the exact payload;
// datagrams without a complete valid header are rejected, never treated as
// raw payload.
func TestParseUDPDatagram(t *testing.T) {
	payload := []byte("proxied application datagram")

	t.Run("v2 PROXY UDPv4 with payload", func(t *testing.T) {
		udpHeader := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv4,
			SourceAddr:        &net.UDPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
			DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
		}
		datagram, err := udpHeader.FormatUDPDatagram(payload)
		if err != nil {
			t.Fatalf("FormatUDPDatagram failed: %v", err)
		}

		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("datagram was rejected: %v", err)
		}
		if !h.EqualsTo(udpHeader) {
			t.Fatalf("expected %#v, actual %#v", udpHeader, h)
		}
		if !bytes.Equal(rest, payload) {
			t.Fatalf("payload = %q, want %q", rest, payload)
		}
	})

	t.Run("v2 LOCAL UNSPEC with payload", func(t *testing.T) {
		datagram := append(v2Header(byte(LOCAL), byte(UNSPEC), nil), payload...)
		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("datagram was rejected: %v", err)
		}
		if !h.Command.IsLocal() {
			t.Fatalf("expected LOCAL command, got %#x", byte(h.Command))
		}
		if !bytes.Equal(rest, payload) {
			t.Fatalf("payload = %q, want %q", rest, payload)
		}
	})

	t.Run("v1 header with payload", func(t *testing.T) {
		datagram := append([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n"), payload...)
		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("datagram was rejected: %v", err)
		}
		if h.Version != 1 {
			t.Fatalf("expected v1 header, got version %d", h.Version)
		}
		if !bytes.Equal(rest, payload) {
			t.Fatalf("payload = %q, want %q", rest, payload)
		}
	})

	t.Run("header only, empty payload", func(t *testing.T) {
		datagram := v2Header(byte(PROXY), byte(UDPv4), make([]byte, int(lengthV4)))
		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("datagram was rejected: %v", err)
		}
		if h == nil || len(rest) != 0 {
			t.Fatalf("expected empty payload, got %q", rest)
		}
	})

	t.Run("no header is not guessed as payload", func(t *testing.T) {
		_, _, err := ParseUDPDatagram([]byte("just application data"))
		if !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})

	t.Run("empty datagram", func(t *testing.T) {
		if _, _, err := ParseUDPDatagram(nil); !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
	})

	t.Run("truncated v2 header", func(t *testing.T) {
		// Declared address block missing entirely: the datagram carries fewer
		// bytes than the header announces, and unlike a stream no more bytes can
		// ever arrive.
		datagram := append(append(bytes.Clone(SIGV2), byte(PROXY), byte(UDPv4)), lengthV4Bytes...)
		if _, _, err := ParseUDPDatagram(datagram); !errors.Is(err, ErrDatagramTruncated) {
			t.Fatalf("expected ErrDatagramTruncated, got %v", err)
		}
	})
}

// TestParseUDPDatagramBoundaries pins the datagram-specific rules that a
// stream parser cannot provide. Each case is a single datagram: there is no
// "next read" to borrow from, so over-declared and truncated frames must be
// rejected with ErrDatagramTruncated instead of being completed.
func TestParseUDPDatagramBoundaries(t *testing.T) {
	payload := []byte("payload")

	baseHeader := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: UDPv4,
		SourceAddr:        &net.UDPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
		DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
	}

	t.Run("header and payload never concatenate across datagrams", func(t *testing.T) {
		// Split one logical datagram at every possible offset into two
		// datagrams. Neither half may produce a header plus payload that
		// matches the original; each half is judged on its own.
		full, err := baseHeader.FormatUDPDatagram(payload)
		if err != nil {
			t.Fatalf("FormatUDPDatagram failed: %v", err)
		}
		wantHeaderLen := len(full) - len(payload)

		// The complete datagram still parses to exactly the payload.
		_, gotPayload, err := ParseUDPDatagram(full)
		if err != nil || !bytes.Equal(gotPayload, payload) {
			t.Fatalf("complete datagram: payload %q err %v", gotPayload, err)
		}

		for split := range len(full) {
			first, second := full[:split], full[split:]

			h, rest, err := ParseUDPDatagram(first)
			if split < wantHeaderLen {
				// A prefix shorter than the header is truncated once the v2
				// signature is visible, and never resumed from the tail.
				if split >= len(SIGV2) && bytes.HasPrefix(first, SIGV2) && !errors.Is(err, ErrDatagramTruncated) {
					t.Fatalf("split %d: expected ErrDatagramTruncated, got %v", split, err)
				}
				continue
			}
			// The prefix contains the whole header, so it is a valid datagram
			// in its own right: its payload is exactly the prefix bytes after
			// the header, never the header remainder from the tail.
			if err != nil {
				t.Fatalf("split %d: complete header rejected: %v", split, err)
			}
			if h == nil {
				t.Fatalf("split %d: nil header", split)
			}
			if want := first[wantHeaderLen:]; !bytes.Equal(rest, want) {
				t.Fatalf("split %d: payload = %q, want %q (tail %q must not be attached)", split, rest, want, second)
			}
		}
	})

	t.Run("declared length larger than datagram is dropped, not completed", func(t *testing.T) {
		// A valid v4 header with one extra byte of declared length, but no such
		// byte in this datagram. Even though a second datagram follows in the
		// caller's buffer, the parser only sees the first.
		headerBytes, err := baseHeader.Format()
		if err != nil {
			t.Fatalf("Format failed: %v", err)
		}
		overDeclared := bytes.Clone(headerBytes)
		binary.BigEndian.PutUint16(overDeclared[14:16], lengthV4+1)

		_, _, err = ParseUDPDatagram(overDeclared)
		if !errors.Is(err, ErrDatagramTruncated) {
			t.Fatalf("expected ErrDatagramTruncated, got %v", err)
		}

		// The over-declared slice is capped at its length: even if the caller's
		// backing array holds a following datagram, that capacity is outside the
		// datagram being parsed and must not repair the header.
		capped := slices.Clip(overDeclared)
		if _, _, err := ParseUDPDatagram(capped); !errors.Is(err, ErrDatagramTruncated) {
			t.Fatalf("spare capacity changed a truncated datagram's result: %v", err)
		}
	})

	t.Run("declared length beyond MaxV2HeaderSize is an invalid length", func(t *testing.T) {
		// The datagram is long enough to hold the declaration, so the only
		// defect is the size cap.
		raw := append(bytes.Clone(SIGV2), byte(PROXY), byte(UDPv4))
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, MaxV2HeaderSize+1)
		raw = append(raw, length...)
		raw = append(raw, make([]byte, int(MaxV2HeaderSize)+1)...)

		if _, _, err := ParseUDPDatagram(raw); !errors.Is(err, ErrInvalidLength) {
			t.Fatalf("expected ErrInvalidLength, got %v", err)
		}

		// Short and over the cap: the truncation is real and must be visible,
		// while the too-large declaration is still reported as its own cause.
		short := raw[:32]
		_, _, err := ParseUDPDatagram(short)
		if !errors.Is(err, ErrDatagramTruncated) || !errors.Is(err, ErrInvalidLength) {
			t.Fatalf("expected both ErrDatagramTruncated and ErrInvalidLength, got %v", err)
		}
	})

	t.Run("truncation errors also report unexpected EOF", func(t *testing.T) {
		// Callers may match either the datagram-specific sentinel or the
		// stream-oriented io.ErrUnexpectedEOF; both must be present.
		cases := [][]byte{
			bytes.Clone(SIGV2[:6]), // signature cut short
			bytes.Clone(SIGV1[:3]), // v1 signature cut short
			append(bytes.Clone(SIGV2), byte(PROXY), byte(UDPv4)),
			append(append(bytes.Clone(SIGV2), byte(PROXY), byte(UDPv4)), lengthV4Bytes...),
			[]byte("PROXY TCP4 1.2.3.4"),
		}
		for _, datagram := range cases {
			_, _, err := ParseUDPDatagram(datagram)
			if !errors.Is(err, ErrDatagramTruncated) || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("datagram %x: expected ErrDatagramTruncated and io.ErrUnexpectedEOF, got %v", datagram, err)
			}
		}
	})

	t.Run("fixed v2 prefix cut short is truncated", func(t *testing.T) {
		for n := len(SIGV2); n < 16; n++ {
			raw := append(bytes.Clone(SIGV2), make([]byte, n-len(SIGV2))...)
			if _, _, err := ParseUDPDatagram(raw); !errors.Is(err, ErrDatagramTruncated) {
				t.Fatalf("prefix of %d bytes: expected ErrDatagramTruncated, got %v", n, err)
			}
		}
	})

	t.Run("v2 header exactly fills datagram and no payload", func(t *testing.T) {
		datagram, err := baseHeader.Format()
		if err != nil {
			t.Fatalf("Format failed: %v", err)
		}
		// Parsing a slice with no capacity left must not read past the header.
		datagram = slices.Clip(datagram)

		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("header-only datagram rejected: %v", err)
		}
		if !h.EqualsTo(baseHeader) {
			t.Fatalf("header mismatch: %#v", h)
		}
		if rest == nil {
			t.Fatal("expected a non-nil empty payload for a non-nil datagram")
		}
		if len(rest) != 0 {
			t.Fatalf("expected empty payload, got %q", rest)
		}
	})

	t.Run("empty datagram", func(t *testing.T) {
		h, rest, err := ParseUDPDatagram([]byte{})
		if !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
		if h != nil || rest != nil {
			t.Fatalf("expected nil header and payload, got %v %q", h, rest)
		}
	})

	t.Run("v1 header without terminate CRLF is truncated", func(t *testing.T) {
		datagram := []byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443")
		if _, _, err := ParseUDPDatagram(datagram); !errors.Is(err, ErrDatagramTruncated) {
			t.Fatalf("expected ErrDatagramTruncated, got %v", err)
		}
	})

	t.Run("v1 line exceeding the maximum length is too long", func(t *testing.T) {
		// 107+ bytes with no LF anywhere: the sender overran the spec limit and
		// no later datagram may be consulted to find the end of the line.
		datagram := append([]byte("PROXY "), bytes.Repeat([]byte{'x'}, 200)...)
		if _, _, err := ParseUDPDatagram(datagram); !errors.Is(err, ErrVersion1HeaderTooLong) {
			t.Fatalf("expected ErrVersion1HeaderTooLong, got %v", err)
		}
	})

	t.Run("payload keeps its exact bytes and length", func(t *testing.T) {
		// Payloads that themselves look like headers or contain NUL / CRLF must
		// be returned verbatim: only the leading header is consumed.
		for _, want := range [][]byte{
			{},
			{0x00},
			[]byte("\r\n"),
			[]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n"),
			append(bytes.Clone(SIGV2), 0xFF),
			bytes.Repeat([]byte{0xAB}, 1400),
		} {
			datagram, err := baseHeader.FormatUDPDatagram(want)
			if err != nil {
				t.Fatalf("FormatUDPDatagram failed: %v", err)
			}
			datagram = slices.Clip(datagram) // no spare capacity: any over-read panics
			_, got, err := ParseUDPDatagram(datagram)
			if err != nil {
				t.Fatalf("payload %x: rejected: %v", want, err)
			}
			if len(got) != len(want) || !bytes.Equal(got, want) {
				t.Fatalf("payload = %x (len %d), want %x (len %d)", got, len(got), want, len(want))
			}
			if len(want) > 0 && &got[0] != &datagram[len(datagram)-len(want)] {
				t.Fatal("payload must alias the datagram, not a copy")
			}
		}
	})

	t.Run("UDPv6 and unknown family", func(t *testing.T) {
		v6 := &Header{
			Version:           2,
			Command:           PROXY,
			TransportProtocol: UDPv6,
			SourceAddr:        &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5353},
			DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443},
		}
		datagram, err := v6.FormatUDPDatagram(payload)
		if err != nil {
			t.Fatalf("FormatUDPDatagram failed: %v", err)
		}
		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("UDPv6 datagram rejected: %v", err)
		}
		src, dst, ok := h.UDPAddrs()
		if !ok || !src.IP.Equal(v6.SourceAddr.(*net.UDPAddr).IP) || src.Port != 5353 ||
			!dst.IP.Equal(v6.DestinationAddr.(*net.UDPAddr).IP) || dst.Port != 443 {
			t.Fatalf("UDPv6 addresses not preserved: %v -> %v", src, dst)
		}
		if !bytes.Equal(rest, payload) {
			t.Fatalf("payload = %q, want %q", rest, payload)
		}

		// UNSPEC under the PROXY command is rejected: an unknown family must
		// not be reported as a valid, local-looking client.
		unspec := &Header{Version: 2, Command: PROXY, TransportProtocol: UNSPEC}
		raw, err := unspec.Format()
		if err != nil {
			t.Fatalf("Format failed: %v", err)
		}
		if _, _, err := ParseUDPDatagram(append(raw, payload...)); !errors.Is(err, ErrUnsupportedAddressFamilyAndProtocol) {
			t.Fatalf("expected ErrUnsupportedAddressFamilyAndProtocol, got %v", err)
		}
	})

	t.Run("LOCAL UNSPEC has no source address", func(t *testing.T) {
		datagram := append(v2Header(byte(LOCAL), byte(UNSPEC), nil), payload...)
		h, rest, err := ParseUDPDatagram(datagram)
		if err != nil {
			t.Fatalf("LOCAL datagram rejected: %v", err)
		}
		if h.SourceAddr != nil || h.DestinationAddr != nil {
			t.Fatalf("LOCAL header must not invent addresses: %v -> %v", h.SourceAddr, h.DestinationAddr)
		}
		if _, _, ok := h.UDPAddrs(); ok {
			t.Fatal("LOCAL UNSPEC must not report UDP addresses")
		}
		if !bytes.Equal(rest, payload) {
			t.Fatalf("payload = %q, want %q", rest, payload)
		}
	})
}

// TestParseUDPDatagramIgnoresTrailingCapacity pins that parsing is limited to
// the header slice and cannot spill into a caller's spare buffer capacity.
func TestParseUDPDatagramIgnoresTrailingCapacity(t *testing.T) {
	header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: UDPv4,
		SourceAddr:        &net.UDPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
		DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
	}
	raw, err := header.Format()
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	// A slice of the header's length but with capacity holding payload bytes:
	// a parser that reads to capacity would append those as the payload.
	buf := make([]byte, len(raw), len(raw)+len("smuggled"))
	copy(buf, raw)
	copy(buf[len(raw):], "smuggled")

	_, rest, err := ParseUDPDatagram(buf)
	if err != nil {
		t.Fatalf("datagram rejected: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("parser read past the datagram length: %q", rest)
	}
}

// TestFormatUDPDatagramError pins that a header that cannot Format surfaces
// the error instead of emitting a datagram with a bogus header.
func TestFormatUDPDatagramError(t *testing.T) {
	h := &Header{Version: 9}
	if _, err := h.FormatUDPDatagram([]byte("payload")); !errors.Is(err, ErrUnknownProxyProtocolVersion) {
		t.Fatalf("expected ErrUnknownProxyProtocolVersion, got %v", err)
	}
}

// FuzzParseUDPDatagram holds the datagram invariants under random input: an
// accepted datagram must re-serialize stably (header format + payload equals a
// datagram that parses to the same result), and the payload must never be
// invented — it is always a suffix of the input.
func FuzzParseUDPDatagram(f *testing.F) {
	f.Add(append(v2Header(byte(PROXY), byte(UDPv4), make([]byte, int(lengthV4))), []byte("payload")...))
	f.Add(append([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443\r\n"), []byte("payload")...))
	f.Add(v2Header(byte(LOCAL), byte(UNSPEC), nil))
	f.Add([]byte("just application data"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parsing must not mutate the caller's datagram.
		original := bytes.Clone(data)
		h, payload, err := ParseUDPDatagram(data)
		if !bytes.Equal(data, original) {
			t.Fatalf("parser mutated its input: %x != %x", data, original)
		}
		if err != nil {
			if h != nil || payload != nil {
				t.Fatalf("error %v returned header %v and payload %q", err, h, payload)
			}
			return
		}
		// An accepted datagram must produce exactly one header; its payload is
		// the datagram's suffix and never a concatenation with anything else.
		if h == nil {
			t.Fatal("accepted datagram returned nil header")
		}
		if !bytes.HasSuffix(data, payload) {
			t.Fatalf("payload %q is not a suffix of the datagram", payload)
		}
		// Round-trip: rebuilding the datagram from the parsed header must
		// yield a datagram that parses to an equal header and byte-identical
		// payload, and re-formats identically (stability).
		out, err := h.FormatUDPDatagram(payload)
		if err != nil {
			t.Fatalf("accepted header failed to FormatUDPDatagram: %v", err)
		}
		h2, payload2, err := ParseUDPDatagram(out)
		if err != nil {
			t.Fatalf("re-parse of formatted datagram failed: %v", err)
		}
		if !bytes.Equal(payload2, payload) {
			t.Fatalf("payload not preserved: %q != %q", payload2, payload)
		}
		out2, err := h2.FormatUDPDatagram(payload2)
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatalf("datagram format not stable: %v\n first  %x\n second %x", err, out, out2)
		}
	})
}
