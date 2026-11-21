package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"reflect"
	"testing"
)

var (
	fixtureOneByteTLV    = []byte{byte(PP2_TYPE_MIN_CUSTOM) + 1}
	fixtureTwoByteTLV    = []byte{byte(PP2_TYPE_MIN_CUSTOM) + 2, 0x00}
	fixtureEmptyLenTLV   = []byte{byte(PP2_TYPE_MIN_CUSTOM) + 3, 0x00, 0x01}
	fixturePartialLenTLV = []byte{byte(PP2_TYPE_MIN_CUSTOM) + 3, 0x00, 0x02, 0x00}
)

var invalidTLVTests = []struct {
	name          string
	reader        *bufio.Reader
	expectedError error
}{
	{
		name: "One byte TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureOneByteTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Two byte TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureTwoByteTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Empty Len TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixtureEmptyLenTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
	{
		name: "Partial Len TLV",
		reader: newBufioReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)), fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address,
			fixturePartialLenTLV)...)),
		expectedError: ErrTruncatedTLV,
	},
}

// TestInvalidV2TLV pins eager TLV validation: the v2 length field delimits the
// whole section, and any TLV whose header is incomplete or whose declared
// value runs past that section is rejected while the header is read, before
// the application can consume any subsequent request on the connection.
func TestInvalidV2TLV(t *testing.T) {
	for _, tc := range invalidTLVTests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Read(tc.reader); !errors.Is(err, tc.expectedError) {
				t.Fatalf("TestInvalidV2TLV %s: expected %#v, actual %#v", tc.name, tc.expectedError, err)
			}
		})
	}
}

// TestTLVZeroLengthRejected pins the framing rule for a complete TLV tuple
// whose value length is zero: only PP2_TYPE_NOOP padding may be empty. A
// non-NOOP zero-length TLV carries no information and is indistinguishable
// from a miscomputed length, so it is rejected with ErrInvalidTLV.
func TestTLVZeroLengthRejected(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)),
		fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, []byte{byte(PP2_TYPE_MIN_CUSTOM), 0x00, 0x00})...)))
	if _, err := Read(r); !errors.Is(err, ErrInvalidTLV) {
		t.Fatalf("expected ErrInvalidTLV for non-NOOP zero-length TLV, got %v", err)
	}
}

// TestTLVZeroLengthNoopAccepted pins the NOOP exception: empty NOOP records
// are valid padding and split into a TLV with no value bytes.
func TestTLVZeroLengthNoopAccepted(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader(append(append(SIGV2, byte(PROXY), byte(TCPv4)),
		fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, []byte{byte(PP2_TYPE_NOOP), 0x00, 0x00})...)))
	h, err := Read(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tlvs, err := h.TLVs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tlvs) != 1 {
		t.Fatalf("expected 1 tlv, got %d", len(tlvs))
	}
	if tlvs[0].Type != PP2_TYPE_NOOP || len(tlvs[0].Value) != 0 {
		t.Fatalf("expected empty NOOP tlv, got %#x value %x", tlvs[0].Type, tlvs[0].Value)
	}
}

// TestTLVLengthOverrunsSection crafts a header whose declared length covers
// the TLV header but not its claimed value. The parser must frame strictly
// against the declared section and reject the frame rather than reading into
// the following request's bytes.
func TestTLVLengthOverrunsSection(t *testing.T) {
	// Address block (12 bytes) + TLV type/length header (3 bytes) = 15, but the
	// TLV claims 4 value bytes and only 1 is present.
	payload := bytes.Clone(fixtureIPv4Address)
	payload = append(payload, byte(PP2_TYPE_MIN_CUSTOM), 0x00, 0x04, 0xAA)
	raw := v2Header(byte(PROXY), byte(TCPv4), payload)
	// Append bytes of the "next request": a strict parser must not consume them.
	raw = append(raw, 'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P')
	r := newBufioReader(raw)
	if _, err := Read(r); !errors.Is(err, ErrTruncatedTLV) {
		t.Fatalf("expected ErrTruncatedTLV for overrun, got %v", err)
	}
}

// TestTLVLengthExceedsMax verifies a syntactically complete TLV whose declared
// length is above MaxTLVLength is rejected with ErrInvalidTLV even though all
// the bytes it claims are inside the section.
func TestTLVLengthExceedsMax(t *testing.T) {
	// A TLV value one byte above the limit, placed in an UNSPEC section so the
	// header length is just the TLV.
	oldMax := MaxTLVLength
	MaxTLVLength = 16
	defer func() { MaxTLVLength = oldMax }()

	rawTLV, err := JoinTLVs([]TLV{{Type: PP2_TYPE_UNIQUE_ID, Value: make([]byte, 17)}})
	if err != nil {
		t.Fatalf("unexpected join error: %v", err)
	}
	raw := v2Header(byte(LOCAL), byte(UNSPEC), rawTLV)
	if _, err := Read(newBufioReader(raw)); !errors.Is(err, ErrInvalidTLV) {
		t.Fatalf("expected ErrInvalidTLV for oversize TLV, got %v", err)
	}

	// A TLV exactly at the limit must still be accepted.
	rawTLV, err = JoinTLVs([]TLV{{Type: PP2_TYPE_UNIQUE_ID, Value: make([]byte, 16)}})
	if err != nil {
		t.Fatalf("unexpected join error: %v", err)
	}
	raw = v2Header(byte(LOCAL), byte(UNSPEC), rawTLV)
	if _, err := Read(newBufioReader(raw)); err != nil {
		t.Fatalf("TLV at MaxTLVLength must parse, got %v", err)
	}
}

func TestV2TLVPP2Registered(t *testing.T) {
	pp2RegTypes := []PP2Type{
		PP2_TYPE_ALPN, PP2_TYPE_AUTHORITY, PP2_TYPE_CRC32C, PP2_TYPE_NOOP, PP2_TYPE_UNIQUE_ID,
		PP2_TYPE_SSL, PP2_SUBTYPE_SSL_VERSION, PP2_SUBTYPE_SSL_CN,
		PP2_SUBTYPE_SSL_CIPHER, PP2_SUBTYPE_SSL_SIG_ALG, PP2_SUBTYPE_SSL_KEY_ALG,
		// Registered in spec v3.4 (2025/2026 revisions).
		PP2_SUBTYPE_SSL_GROUP, PP2_SUBTYPE_SSL_SIG_SCHEME, PP2_SUBTYPE_SSL_CLIENT_CERT,
		PP2_TYPE_NETNS,
	}
	pp2RegMap := make(map[PP2Type]bool)
	for _, p := range pp2RegTypes {
		pp2RegMap[p] = true
		if !p.Registered() {
			t.Fatalf("TestV2TLVPP2Registered: type %x should be registered", p)
		}
		if !p.Spec() {
			t.Fatalf("TestV2TLVPP2Registered: type %x should be in spec", p)
		}
		if p.App() {
			t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly app", p)
		}
		if p.Experiment() {
			t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly experiment", p)
		}
		if p.Future() {
			t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly future", p)
		}
	}

	lastType := PP2Type(0xFF)
	for i := range int(lastType) {
		p := PP2Type(i)
		if !pp2RegMap[p] && p.Registered() {
			t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly registered", p)
		}
	}

	if lastType.Registered() {
		t.Fatalf("TestV2TLVPP2Registered: type %x unexpectedly registered", lastType)
	}
}

func TestJoinTLVs(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		tlvs []TLV
	}{
		{
			name: "authority TLV",
			raw:  append([]byte{byte(PP2_TYPE_AUTHORITY), 0x00, 0x0B}, []byte("example.org")...),
			tlvs: []TLV{{
				Type:  PP2_TYPE_AUTHORITY,
				Value: []byte("example.org"),
			}},
		},
		{
			name: "empty TLV",
			raw:  []byte{byte(PP2_TYPE_NOOP), 0x00, 0x00},
			tlvs: []TLV{{
				Type:  PP2_TYPE_NOOP,
				Value: nil,
			}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if raw, err := JoinTLVs(tc.tlvs); err != nil {
				t.Fatalf("unexpected error: %v", err)
			} else if !bytes.Equal(raw, tc.raw) {
				t.Errorf("expected %#v, got %#v", tc.raw, raw)
			}
		})
	}
}

// TestPP2TypeReservedRanges pins the App/Experiment/Future/Spec classification
// at the boundaries of the reserved ranges from spec section 2.2.8, which the
// exhaustive Registered sweep in TestV2TLVPP2Registered does not cover.
func TestPP2TypeReservedRanges(t *testing.T) {
	for _, tc := range []struct {
		typ                     PP2Type
		app, experiment, future bool
	}{
		{typ: 0x00}, // unassigned
		{typ: 0x06}, // unassigned, just past UNIQUE_ID
		{typ: 0x29}, // unassigned, just past SSL_CLIENT_CERT
		{typ: 0xDF}, // unassigned, just before custom range
		{typ: PP2_TYPE_MIN_CUSTOM, app: true},
		{typ: PP2_TYPE_MAX_CUSTOM, app: true},
		{typ: PP2_TYPE_MIN_EXPERIMENT, experiment: true},
		{typ: PP2_TYPE_MAX_EXPERIMENT, experiment: true},
		{typ: PP2_TYPE_MIN_FUTURE, future: true},
		{typ: PP2_TYPE_MAX_FUTURE, future: true},
	} {
		if tc.typ.Registered() {
			t.Errorf("type %#x must not be Registered", byte(tc.typ))
		}
		if got := tc.typ.App(); got != tc.app {
			t.Errorf("type %#x: App() = %v, want %v", byte(tc.typ), got, tc.app)
		}
		if got := tc.typ.Experiment(); got != tc.experiment {
			t.Errorf("type %#x: Experiment() = %v, want %v", byte(tc.typ), got, tc.experiment)
		}
		if got := tc.typ.Future(); got != tc.future {
			t.Errorf("type %#x: Future() = %v, want %v", byte(tc.typ), got, tc.future)
		}
		reserved := tc.app || tc.experiment || tc.future
		if got := tc.typ.Spec(); got != reserved {
			t.Errorf("type %#x: Spec() = %v, want %v", byte(tc.typ), got, reserved)
		}
	}
}

// buildV2TLVHeader assembles a complete v2 header with an UNSPEC transport
// whose TLV section is exactly rawTLVs, under the given command.
func buildV2TLVHeader(command byte, rawTLVs []byte) *Header {
	r := newBufioReader(append(append(SIGV2, command, byte(UNSPEC)),
		fixtureWithTLV(lengthUnspecBytes, nil, rawTLVs)...))
	h, err := Read(r)
	if err != nil {
		panic(err)
	}
	return h
}

// TestUnknownTLVPreserved verifies requirement 3: TLVs of types the library
// does not know (custom, experimental, future and unassigned alike) are not
// rejected; their raw value bytes survive parsing untouched and remain
// inspectable by upper layers, interleaved with known types.
func TestUnknownTLVPreserved(t *testing.T) {
	raw := mustJoinTLVs(
		TLV{Type: PP2_TYPE_ALPN, Value: []byte("h2")},
		TLV{Type: PP2_TYPE_MIN_CUSTOM, Value: []byte{0xCA, 0xFE}},
		TLV{Type: PP2_TYPE_MAX_EXPERIMENT, Value: []byte{0xBA, 0xBE}},
		TLV{Type: PP2_TYPE_MAX_FUTURE, Value: []byte{0xF0, 0x0D}},
		TLV{Type: PP2Type(0x06), Value: []byte{0x12, 0x34}}, // unassigned, just past UNIQUE_ID
		TLV{Type: PP2_TYPE_AUTHORITY, Value: []byte("example.org")},
	)
	h := buildV2TLVHeader(byte(LOCAL), raw)
	tlvs, err := h.TLVs()
	if err != nil {
		t.Fatalf("unknown types must not break parsing: %v", err)
	}
	if len(tlvs) != 6 {
		t.Fatalf("expected 6 TLVs in wire order, got %d", len(tlvs))
	}
	wantTypes := []PP2Type{PP2_TYPE_ALPN, PP2_TYPE_MIN_CUSTOM, PP2_TYPE_MAX_EXPERIMENT, PP2_TYPE_MAX_FUTURE, PP2Type(0x06), PP2_TYPE_AUTHORITY}
	for i, want := range wantTypes {
		if tlvs[i].Type != want {
			t.Fatalf("tlv %d: type = %#x, want %#x", i, tlvs[i].Type, want)
		}
	}
	if !bytes.Equal(tlvs[1].Value, []byte{0xCA, 0xFE}) || !bytes.Equal(tlvs[3].Value, []byte{0xF0, 0x0D}) {
		t.Fatalf("unknown TLV value bytes were not preserved: %#v", tlvs)
	}
	// Known-type parsing alongside unknown types keeps working.
	if alpn, err := h.TLVsByType(PP2_TYPE_ALPN); err != nil || len(alpn) != 1 || string(alpn[0].Value) != "h2" {
		t.Fatalf("known ALPN lookup failed alongside unknown TLVs: %#v err=%v", alpn, err)
	}
	// Round-trip must reproduce the section byte for byte (NOOP absent here, so
	// nothing is canonicalized away).
	out, err := h.Format()
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	if !bytes.Contains(out, raw) {
		t.Fatalf("formatted header lost unknown TLV bytes\n got  %x\n want section %x", out, raw)
	}
}

// TestDuplicateKnownTLVsOrdered verifies requirement 4: when a known type
// appears more than once, every occurrence is exposed in wire order and the
// first value is not silently overwritten by the second.
func TestDuplicateKnownTLVsOrdered(t *testing.T) {
	raw := mustJoinTLVs(
		TLV{Type: PP2_TYPE_AUTHORITY, Value: []byte("first.example")},
		TLV{Type: PP2_TYPE_NOOP, Value: nil},
		TLV{Type: PP2_TYPE_AUTHORITY, Value: []byte("second.example")},
	)
	h := buildV2TLVHeader(byte(LOCAL), raw)

	tlvs, err := h.TLVs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tlvs) != 3 {
		t.Fatalf("expected all three records (incl. NOOP), got %d", len(tlvs))
	}
	authorities, err := h.TLVsByType(PP2_TYPE_AUTHORITY)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(authorities) != 2 {
		t.Fatalf("expected both AUTHORITY occurrences, got %d", len(authorities))
	}
	if string(authorities[0].Value) != "first.example" || string(authorities[1].Value) != "second.example" {
		t.Fatalf("duplicate TLVs out of order or overwritten: %q, %q", authorities[0].Value, authorities[1].Value)
	}
	// The free function behaves identically on an arbitrary TLV slice.
	if got := FindTLVs(tlvs, PP2_TYPE_AUTHORITY); len(got) != 2 ||
		string(got[0].Value) != "first.example" {
		t.Fatalf("FindTLVs did not return duplicates in order: %#v", got)
	}
	if got := FindTLVs(tlvs, PP2_TYPE_NETNS); got != nil {
		t.Fatalf("FindTLVs for absent type must be nil, got %#v", got)
	}
}

// TestLocalAndUnknownFramesCarryTLVsButNotAddresses verifies requirement 5:
// LOCAL and UNKNOWN-via-UNSPEC frames may carry extension fields, but they can
// never be used as a source address — neither through the Header nor through
// Conn.RemoteAddr.
func TestLocalAndUnknownFramesCarryTLVsButNotAddresses(t *testing.T) {
	rawTLV := mustJoinTLVs(TLV{Type: PP2_TYPE_ALPN, Value: []byte("h2")})

	for _, tc := range []struct {
		desc      string
		command   byte
		transport byte
	}{
		{"LOCAL UNSPEC", byte(LOCAL), byte(UNSPEC)},
		{"LOCAL TCPv4 full block", byte(LOCAL), byte(TCPv4)},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var frame []byte
			if tc.transport == byte(UNSPEC) {
				frame = append(append(SIGV2, tc.command, tc.transport),
					fixtureWithTLV(lengthUnspecBytes, nil, rawTLV)...)
			} else {
				frame = append(append(SIGV2, tc.command, tc.transport),
					fixtureWithTLV(lengthV4Bytes, fixtureIPv4Address, rawTLV)...)
			}

			clientConn, serverConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()
			defer func() { _ = serverConn.Close() }()
			go func() { _, _ = clientConn.Write(frame) }()

			c := NewConn(serverConn)
			if err := c.ReadHeaderError(); err != nil {
				t.Fatalf("LOCAL frame with TLVs must be accepted: %v", err)
			}
			hdr := c.ProxyHeader()
			if hdr == nil || !hdr.Command.IsLocal() {
				t.Fatalf("expected LOCAL header, got %#v", hdr)
			}
			tlvs, err := hdr.TLVs()
			if err != nil {
				t.Fatalf("LOCAL frame must expose extension fields: %v", err)
			}
			if len(tlvs) != 1 || tlvs[0].Type != PP2_TYPE_ALPN {
				t.Fatalf("LOCAL TLVs not preserved: %#v", tlvs)
			}
			// The address advertised inside a LOCAL frame must not be presented
			// as the peer's source address; the real connection endpoint wins.
			if got := c.RemoteAddr(); got != serverConn.RemoteAddr() {
				t.Fatalf("LOCAL frame must not spoof RemoteAddr: got %v want %v", got, serverConn.RemoteAddr())
			}
			if got := c.LocalAddr(); got != serverConn.LocalAddr() {
				t.Fatalf("LOCAL frame must not spoof LocalAddr: got %v want %v", got, serverConn.LocalAddr())
			}
		})
	}
}

// TestTLVParseCacheAndSetTLVs verifies the parsed vector is cached at read
// time (repeated TLVs calls return the same result without re-splitting), and
// that SetTLVs refreshes the cache but rejects framing violations without
// touching the header's previous state.
func TestTLVParseCacheAndSetTLVs(t *testing.T) {
	raw := mustJoinTLVs(
		TLV{Type: PP2_TYPE_ALPN, Value: []byte("h2")},
		TLV{Type: PP2_TYPE_MIN_CUSTOM, Value: []byte{0x01}},
	)
	h := buildV2TLVHeader(byte(LOCAL), raw)
	first, err := h.TLVs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := h.TLVs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(first) != 2 || !reflect.DeepEqual(first, second) {
		t.Fatalf("cached TLV parse is unstable: %#v vs %#v", first, second)
	}

	if err := h.SetTLVs([]TLV{{Type: PP2_TYPE_AUTHORITY, Value: []byte("example.org")}}); err != nil {
		t.Fatalf("SetTLVs failed: %v", err)
	}
	got, err := h.TLVs()
	if err != nil || len(got) != 1 || got[0].Type != PP2_TYPE_AUTHORITY {
		t.Fatalf("SetTLVs did not refresh the parsed vector: %#v err=%v", got, err)
	}
	byType, err := h.TLVsByType(PP2_TYPE_AUTHORITY)
	if err != nil || len(byType) != 1 || string(byType[0].Value) != "example.org" {
		t.Fatalf("TLVsByType after SetTLVs failed: %#v err=%v", byType, err)
	}

	// A framing violation (zero-length non-NOOP TLV) must be reported and must
	// not replace the header's previously valid vector.
	err = h.SetTLVs([]TLV{{Type: PP2_TYPE_ALPN}})
	if !errors.Is(err, ErrInvalidTLV) {
		t.Fatalf("expected ErrInvalidTLV from SetTLVs, got %v", err)
	}
	got, err = h.TLVs()
	if err != nil || len(got) != 1 || got[0].Type != PP2_TYPE_AUTHORITY {
		t.Fatalf("failed SetTLVs must leave the previous vector intact: %#v err=%v", got, err)
	}
}
