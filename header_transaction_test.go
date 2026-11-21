package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// This file pins the unified header-transaction semantics of a listener that
// receives v1, v2 and ordinary protocol traffic on the same socket: a single
// read transaction must pick the version, apply the policy and deliver the
// body exactly once.

// newBufioReaderOver builds a buffer over data identical to how a Conn buffers
// its underlying connection, so the Read() level tests exercise the same
// buffer sizing the production path uses.
func newHeaderReader(data []byte) *bufio.Reader {
	return bufio.NewReaderSize(bytes.NewReader(data), readBufferSize)
}

// TestReadMinimalSafePrefixMatching covers unified-header rule 1: detection
// first matches the minimal safe prefix, then selects v1 or v2. A prefix of a
// signature cut short by a clean EOF is an incomplete PROXY header and must
// never be reported as ErrNoProxyProtocol (i.e. misjudged as headerless).
func TestReadMinimalSafePrefixMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "empty stream is headerless", data: nil, want: ErrNoProxyProtocol},
		{name: "ordinary traffic is headerless", data: []byte("GET / HTTP/1.1\r\n"), want: ErrNoProxyProtocol},
		{name: "unrelated first byte is headerless", data: []byte("X-PROXY"), want: ErrNoProxyProtocol},

		// v1 signature prefixes, each ending before the 5-byte signature is
		// complete.
		{name: "v1 prefix one byte", data: SIGV1[:1], want: ErrIncompleteProxyProtocolSignature},
		{name: "v1 prefix four bytes", data: SIGV1[:4], want: ErrIncompleteProxyProtocolSignature},

		// v2 signature prefixes of every length 1..11: none may be guessed as a
		// headerless stream, regardless of where the truncation lands.
		{name: "v2 prefix one byte", data: SIGV2[:1], want: ErrIncompleteProxyProtocolSignature},
		{name: "v2 prefix six bytes", data: SIGV2[:6], want: ErrIncompleteProxyProtocolSignature},
		{name: "v2 prefix eleven bytes", data: SIGV2[:11], want: ErrIncompleteProxyProtocolSignature},
		// A fragment that happens to start inside the signature still carries the
		// shared first byte (SIGV2[2:][0] == 0x0d == SIGV2[0]).
		{name: "v2 interior fragment", data: SIGV2[2:], want: ErrIncompleteProxyProtocolSignature},

		// Once enough bytes disprove v1, a still-short v2 peek keeps the
		// truncation verdict; a full 12-byte peek that disproves v2 is a genuine
		// no-header result.
		{name: "v1 disproven, v2 still truncated", data: append([]byte("PROXX"), SIGV2[:6]...), want: ErrIncompleteProxyProtocolSignature},
		{name: "both signatures disproven", data: append([]byte("PROXX"), bytes.Repeat([]byte{'Z'}, 7)...), want: ErrNoProxyProtocol},
		{name: "twelve bytes wrong last v2 byte", data: append(append([]byte{}, SIGV2[:11]...), 'X'), want: ErrNoProxyProtocol},

		// A complete signature followed by EOF inside the header body is a parse
		// error, not a no-header guess.
		{name: "full v1 signature then EOF", data: []byte("PROXY TCP4 1.2.3.4 5.6.7.8 80 443"), want: ErrCantReadVersion1Header},
		{name: "full v2 signature then EOF", data: bytes.Clone(SIGV2), want: ErrCantReadProtocolVersionAndCommand},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reader := newHeaderReader(tt.data)
			_, err := Read(reader)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Read(%q) error = %v, want %v", tt.data, err, tt.want)
			}
			// The incomplete verdict must wrap io.ErrUnexpectedEOF so callers
			// can distinguish a cut-short header from a transport failure.
			if errors.Is(err, ErrIncompleteProxyProtocolSignature) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("incomplete-signature error should wrap io.ErrUnexpectedEOF, got %v", err)
			}
			// A headerless verdict leaves every byte buffered and untouched.
			if errors.Is(err, ErrNoProxyProtocol) && reader.Buffered() != len(tt.data) {
				t.Fatalf("no-header path consumed bytes: buffered=%d want=%d", reader.Buffered(), len(tt.data))
			}
		})
	}
}

// TestReadPropagatesTransportErrorOnTruncatedPrefix ensures a non-EOF
// transport error while reading a signature prefix is never flattened into
// either header verdict: the underlying error must reach the caller.
func TestReadPropagatesTransportErrorOnTruncatedPrefix(t *testing.T) {
	t.Parallel()
	errBoom := errors.New("boom")
	for _, tc := range []struct {
		desc   string
		prefix []byte
	}{
		{"v1 prefix", []byte("PR")},
		{"v2 prefix", SIGV2[:6]},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			r := bufio.NewReader(&prefixErrReader{data: tc.prefix, err: errBoom})
			if _, err := Read(r); !errors.Is(err, errBoom) {
				t.Fatalf("expected transport error to propagate, got %v", err)
			}
		})
	}
}

// TestMixedVersionTrafficOnOneReader feeds v1, v2 and ordinary frames through
// independent Read transactions over fresh buffers, pinning version selection
// on the same listener surface (rule 1 and rule 4).
func TestMixedVersionTrafficOnOneReader(t *testing.T) {
	t.Parallel()

	v1Frame := []byte("PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n")
	v2Header := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("10.1.1.1"), Port: 1000},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("20.2.2.2"), Port: 2000},
	}
	v2Frame := mustFormat(t, v2Header)
	plainFrame := []byte("plain application bytes")

	frames := []struct {
		name    string
		data    []byte
		version byte // 0 means no header expected
	}{
		{"v1", v1Frame, 1},
		{"v2", v2Frame, 2},
		{"plain", plainFrame, 0},
		{"v2 again", v2Frame, 2},
		{"v1 again", v1Frame, 1},
		{"plain again", plainFrame, 0},
	}
	for _, fr := range frames {
		t.Run(fr.name, func(t *testing.T) {
			t.Parallel()
			reader := newHeaderReader(fr.data)
			header, err := Read(reader)
			if fr.version == 0 {
				if !errors.Is(err, ErrNoProxyProtocol) {
					t.Fatalf("plain frame: expected ErrNoProxyProtocol, got %v", err)
				}
				// Every plain byte must still be available after detection.
				rest, readErr := io.ReadAll(reader)
				if readErr != nil || !bytes.Equal(rest, fr.data) {
					t.Fatalf("plain frame bytes not preserved: rest=%q err=%v", rest, readErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("frame %s: unexpected error %v", fr.name, err)
			}
			if header.Version != fr.version {
				t.Fatalf("frame %s: version=%d want %d", fr.name, header.Version, fr.version)
			}
			if got := header.SourceAddr.String(); got != "10.1.1.1:1000" {
				t.Fatalf("frame %s: source addr %q", fr.name, got)
			}
		})
	}
}

// TestBodyPrefixDeliveredExactlyOnce covers rule 2: after version selection the
// parser reads only the declared section; body bytes that arrived in the same
// TCP segment stay in the connection buffer and are handed to the application
// exactly once, never duplicated or dropped. Both v1 and v2 are exercised,
// including a body larger than the detection buffer so a refill is required.
func TestBodyPrefixDeliveredExactlyOnce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		header     *Header
		rawV1      []byte // when set, used verbatim instead of header.Format()
		body       []byte
		bufferSize int // 0 uses the default; >0 sets an explicit small buffer
	}{
		{
			name:  "v1 header with body in same segment",
			rawV1: []byte("PROXY TCP4 10.1.1.1 20.2.2.2 1000 2000\r\n"),
			body:  []byte("ping"),
		},
		{
			name:   "v2 header with body in same segment",
			header: testTCPv4Header(),
			body:   []byte("ping"),
		},
		{
			name:       "v2 header with body spanning refills",
			header:     testTCPv4Header(),
			body:       bytes.Repeat([]byte("Z"), 4096),
			bufferSize: readBufferSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var frame []byte
			if tt.rawV1 != nil {
				frame = append(frame, tt.rawV1...)
			} else {
				frame = append(frame, mustFormat(t, tt.header)...)
			}
			frame = append(frame, tt.body...)

			server, client := net.Pipe()
			t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
			go func() {
				_, _ = client.Write(frame)
			}()

			opts := []func(*Conn){WithPolicy(REQUIRE), SetReadHeaderTimeout(time.Second)}
			if tt.bufferSize > 0 {
				opts = append(opts, WithBufferSize(tt.bufferSize))
			}
			conn := NewConn(server, opts...)
			got := make([]byte, len(tt.body))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("reading body: %v", err)
			}
			if !bytes.Equal(got, tt.body) {
				t.Fatalf("body mismatch: got %d bytes, want %d", len(got), len(tt.body))
			}

			// The header section itself must never leak into the body stream.
			if bytes.Contains(got, SIGV1) || bytes.Contains(got, SIGV2) {
				t.Fatal("signature bytes leaked into the delivered body")
			}

			// A second read after the exact body must not re-deliver any buffered
			// bytes: the transaction delivered the body precisely once.
			_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			one := make([]byte, 1)
			if n, err := conn.Read(one); err == nil {
				t.Fatalf("unexpected extra buffered byte after body: n=%d %q", n, one[:n])
			}
		})
	}
}

// TestRepeatedReadDoesNotReprocessHeader covers rule 5's repeated-read half:
// the header transaction runs at most once. Subsequent Reads return the same
// terminal result and never re-enter parsing, so no additional buffering or a
// different address can ever be observed.
func TestRepeatedReadDoesNotReprocessHeader(t *testing.T) {
	t.Parallel()

	t.Run("successful header is stable across reads", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		go func() {
			_, _ = testTCPv4Header().WriteTo(client)
			_, _ = client.Write([]byte("abc"))
		}()

		conn := NewConn(server, WithPolicy(REQUIRE), SetReadHeaderTimeout(time.Second))
		first := make([]byte, 1)
		if _, err := io.ReadFull(conn, first); err != nil {
			t.Fatalf("first read: %v", err)
		}
		h1 := conn.ProxyHeader()
		addr1 := conn.RemoteAddr().String()

		rest := make([]byte, 2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			t.Fatalf("second read: %v", err)
		}
		if string(append(first, rest...)) != "abc" {
			t.Fatalf("body split across reads was not preserved: %q", append(first, rest...))
		}
		if conn.ProxyHeader() != h1 {
			t.Fatal("header object changed between reads")
		}
		if conn.RemoteAddr().String() != addr1 {
			t.Fatalf("remote addr changed between reads: %q vs %q", conn.RemoteAddr(), addr1)
		}
	})

	t.Run("terminal error is deterministic and repeated", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		// A truncated v2 signature followed by a clean close.
		go func() {
			_, _ = client.Write(SIGV2[:6])
			_ = client.Close()
		}()

		conn := NewConn(server, WithPolicy(USE), SetReadHeaderTimeout(time.Second))
		_, firstErr := conn.Read(make([]byte, 1))
		if !errors.Is(firstErr, ErrIncompleteProxyProtocolSignature) {
			t.Fatalf("first read: expected incomplete-signature error, got %v", firstErr)
		}
		// Repeated reads must surface the identical result and never fall through
		// to a raw read (which would expose the signature prefix as body).
		for range 3 {
			_, err := conn.Read(make([]byte, 1))
			if !errors.Is(err, firstErr) {
				t.Fatalf("repeated read changed the result: %v vs %v", err, firstErr)
			}
		}
		if h := conn.ProxyHeader(); h != nil {
			t.Fatalf("a failed transaction must not retain a header, got %+v", h)
		}
	})
}

// TestTruncatedHeaderBoundedBuffering covers rule 5's unbounded-buffering half:
// a peer that streams arbitrary bytes after a v1 signature cannot make the
// parser buffer without limit. v1 parsing caps the line at 107 bytes and v2 at
// the declared length / MaxV2HeaderSize, and both fail closed.
func TestTruncatedHeaderBoundedBuffering(t *testing.T) {
	t.Parallel()

	t.Run("v1 line over 107 bytes fails closed", func(t *testing.T) {
		t.Parallel()
		// No CRLF anywhere: the parser must stop at the 107-byte cap instead of
		// buffering the whole stream.
		overlong := append([]byte("PROXY TCP4 "), bytes.Repeat([]byte{'A'}, 4096)...)
		_, err := Read(newHeaderReader(overlong))
		if !errors.Is(err, ErrVersion1HeaderTooLong) {
			t.Fatalf("expected ErrVersion1HeaderTooLong, got %v", err)
		}
	})

	t.Run("v2 declared length beyond cap fails closed", func(t *testing.T) {
		t.Parallel()
		raw := v2Header(byte(PROXY), byte(TCPv4), make([]byte, int(MaxV2HeaderSize)+64))
		_, err := Read(newHeaderReader(raw))
		if !errors.Is(err, ErrInvalidLength) {
			t.Fatalf("expected ErrInvalidLength, got %v", err)
		}
	})
}

// mustFormat renders a header or fails the test, keeping table-driven cases
// terse.
func mustFormat(t *testing.T, h *Header) []byte {
	t.Helper()
	b, err := h.Format()
	if err != nil {
		t.Fatalf("header.Format: %v", err)
	}
	return b
}
