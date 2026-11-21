// Type-Length-Value splitting and parsing for proxy protocol V2.
// See spec https://www.haproxy.org/download/3.4/doc/proxy-protocol.txt sections 2.2 to 2.2.8.

package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// TLV type constants defined by the PROXY protocol spec.
//
//nolint:revive // Names follow the spec.
const (
	// Section 2.2.
	PP2_TYPE_ALPN               PP2Type = 0x01
	PP2_TYPE_AUTHORITY          PP2Type = 0x02
	PP2_TYPE_CRC32C             PP2Type = 0x03
	PP2_TYPE_NOOP               PP2Type = 0x04
	PP2_TYPE_UNIQUE_ID          PP2Type = 0x05
	PP2_TYPE_SSL                PP2Type = 0x20
	PP2_SUBTYPE_SSL_VERSION     PP2Type = 0x21
	PP2_SUBTYPE_SSL_CN          PP2Type = 0x22
	PP2_SUBTYPE_SSL_CIPHER      PP2Type = 0x23
	PP2_SUBTYPE_SSL_SIG_ALG     PP2Type = 0x24
	PP2_SUBTYPE_SSL_KEY_ALG     PP2Type = 0x25
	PP2_SUBTYPE_SSL_GROUP       PP2Type = 0x26
	PP2_SUBTYPE_SSL_SIG_SCHEME  PP2Type = 0x27
	PP2_SUBTYPE_SSL_CLIENT_CERT PP2Type = 0x28
	PP2_TYPE_NETNS              PP2Type = 0x30

	// Section 2.2.8, reserved types.
	PP2_TYPE_MIN_CUSTOM     PP2Type = 0xE0
	PP2_TYPE_MAX_CUSTOM     PP2Type = 0xEF
	PP2_TYPE_MIN_EXPERIMENT PP2Type = 0xF0
	PP2_TYPE_MAX_EXPERIMENT PP2Type = 0xF7
	PP2_TYPE_MIN_FUTURE     PP2Type = 0xF8
	PP2_TYPE_MAX_FUTURE     PP2Type = 0xFF
)

// MaxTLVLength is the maximum accepted length field of a single v2 TLV value.
//
// The on-wire field is 16 bits and allows up to 65535, but a TLV that large
// inside a header already bounded by MaxV2HeaderSize can only be a framing
// error (a miscomputed length that would consume subsequent TLVs, or bytes
// belonging to the next request). Rejecting it as a protocol error keeps such
// a frame from being accepted and corrupting the following request, while the
// default stays above the largest real-world TLV
// (PP2_SUBTYPE_SSL_CLIENT_CERT, typically 1..2 KiB).
//
// Like MaxV2HeaderSize, this is a package-level variable so deployments can
// raise it. Set it at program init; it must not be modified concurrently with
// parsing.
var MaxTLVLength uint16 = 4096

var (
	// ErrTruncatedTLV indicates a TLV was truncated: its header is incomplete
	// or its declared length runs past the end of the TLV vector (which, for a
	// header parsed off the wire, is itself bounded by the v2 length field).
	ErrTruncatedTLV = errors.New("proxyproto: truncated TLV")
	// ErrMalformedTLV indicates a TLV has malformed data.
	ErrMalformedTLV = errors.New("proxyproto: malformed TLV Value")
	// ErrIncompatibleTLV indicates a TLV is of an unexpected type.
	ErrIncompatibleTLV = errors.New("proxyproto: incompatible TLV type")
	// ErrInvalidTLV indicates a TLV whose framing is invalid even though every
	// byte it claims is present: a non-NOOP TLV with a zero length, or a
	// declared length above MaxTLVLength. PP2_TYPE_NOOP padding may legally
	// carry an empty value and is exempt.
	ErrInvalidTLV = errors.New("proxyproto: invalid TLV")
)

// PP2Type is the proxy protocol v2 type.
type PP2Type byte

// TLV is a uninterpreted Type-Length-Value for V2 protocol, see section 2.2.
type TLV struct {
	Type  PP2Type
	Value []byte
}

// SplitTLVs splits the Type-Length-Value vector, returns the vector or an
// error.
//
// raw must be exactly the TLV section of a v2 header: parseVersion2 first
// delimits the whole v2 payload (address block plus TLVs) by the header's
// declared 16-bit length, so every TLV is checked against the same boundary
// the sender declared rather than against whatever bytes follow on the
// connection. The failure modes are:
//
//   - ErrTruncatedTLV: fewer than three bytes remain for a TLV header, or the
//     declared value length extends past the end of raw. A TLV that claims
//     bytes beyond the section cannot be framed safely and must not be read
//     into the next request's data.
//   - ErrInvalidTLV: a non-NOOP TLV declares a zero length, or a length above
//     MaxTLVLength. NOOP is padding and may be empty.
//
// Unknown TLV types are never rejected: their raw value bytes are preserved
// verbatim for upper layers. Every TLV, including duplicates of a known type,
// is appended in wire order; callers see all occurrences instead of the last
// one silently overwriting earlier ones.
func SplitTLVs(raw []byte) ([]TLV, error) {
	var tlvs []TLV
	for i := 0; i < len(raw); {
		// A TLV needs its one-byte type and two-byte length before any value.
		if len(raw)-i < 3 {
			return nil, ErrTruncatedTLV
		}
		tlv := TLV{
			Type: PP2Type(raw[i]),
		}
		tlvLen := int(binary.BigEndian.Uint16(raw[i+1 : i+3]))
		// The value must stay inside the section the header declared; otherwise
		// framing the TLV would consume bytes of the next request.
		if tlvLen > len(raw)-(i+3) {
			return nil, ErrTruncatedTLV
		}
		if tlvLen > int(MaxTLVLength) {
			return nil, fmt.Errorf("%w: type %#x length %d exceeds %d", ErrInvalidTLV, byte(tlv.Type), tlvLen, MaxTLVLength)
		}
		// NOOP padding may legitimately carry no value; every other type with
		// a zero length is an unambiguously malformed frame.
		if tlvLen == 0 && tlv.Type != PP2_TYPE_NOOP {
			return nil, fmt.Errorf("%w: type %#x has zero length", ErrInvalidTLV, byte(tlv.Type))
		}
		i += 3
		// Ignore no-op padding
		if tlv.Type != PP2_TYPE_NOOP {
			tlv.Value = make([]byte, tlvLen)
			copy(tlv.Value, raw[i:i+tlvLen])
		}
		i += tlvLen
		tlvs = append(tlvs, tlv)
	}
	return tlvs, nil
}

// FindTLVs returns every TLV of the given type, in wire order. A header that
// repeats a known type exposes all occurrences rather than only the last one;
// callers that want a single value can take the first element. Unknown types
// are included like any other, with their raw value bytes preserved.
func FindTLVs(tlvs []TLV, typ PP2Type) []TLV {
	var found []TLV
	for _, tlv := range tlvs {
		if tlv.Type == typ {
			found = append(found, tlv)
		}
	}
	return found
}

// JoinTLVs joins multiple Type-Length-Value records.
func JoinTLVs(tlvs []TLV) ([]byte, error) {
	var raw []byte
	for _, tlv := range tlvs {
		if len(tlv.Value) > math.MaxUint16 {
			return nil, fmt.Errorf("proxyproto: cannot format TLV %v with length %d", tlv.Type, len(tlv.Value))
		}
		var length [2]byte
		//nolint:gosec // lengthValue is validated above.
		lengthValue := uint16(len(tlv.Value))
		binary.BigEndian.PutUint16(length[:], lengthValue)
		raw = append(raw, byte(tlv.Type))
		raw = append(raw, length[:]...)
		raw = append(raw, tlv.Value...)
	}
	return raw, nil
}

// Registered is true if the type is registered in the spec, see section 2.2.
func (p PP2Type) Registered() bool {
	switch p {
	case PP2_TYPE_ALPN,
		PP2_TYPE_AUTHORITY,
		PP2_TYPE_CRC32C,
		PP2_TYPE_NOOP,
		PP2_TYPE_UNIQUE_ID,
		PP2_TYPE_SSL,
		PP2_SUBTYPE_SSL_VERSION,
		PP2_SUBTYPE_SSL_CN,
		PP2_SUBTYPE_SSL_CIPHER,
		PP2_SUBTYPE_SSL_SIG_ALG,
		PP2_SUBTYPE_SSL_KEY_ALG,
		PP2_SUBTYPE_SSL_GROUP,
		PP2_SUBTYPE_SSL_SIG_SCHEME,
		PP2_SUBTYPE_SSL_CLIENT_CERT,
		PP2_TYPE_NETNS:
		return true
	}
	return false
}

// App is true if the type is reserved for application specific data, see section 2.2.8.
func (p PP2Type) App() bool {
	return p >= PP2_TYPE_MIN_CUSTOM && p <= PP2_TYPE_MAX_CUSTOM
}

// Experiment is true if the type is reserved for temporary experimental use by application
// developers, see section 2.2.8.
func (p PP2Type) Experiment() bool {
	return p >= PP2_TYPE_MIN_EXPERIMENT && p <= PP2_TYPE_MAX_EXPERIMENT
}

// Future is true is the type is reserved for future use, see section 2.2.8.
func (p PP2Type) Future() bool {
	return p >= PP2_TYPE_MIN_FUTURE
}

// Spec is true if the type is covered by the spec, see section 2.2 and 2.2.8.
func (p PP2Type) Spec() bool {
	return p.Registered() || p.App() || p.Experiment() || p.Future()
}
