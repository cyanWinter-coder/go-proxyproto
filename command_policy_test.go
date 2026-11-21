package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

// forgedLocalV2Header returns a v2 LOCAL frame carrying a full, forged TCPv4
// address block: the shape a proxy health check (or an attacker imitating
// one) puts on the wire.
func forgedLocalV2Header(t *testing.T) []byte {
	t.Helper()
	raw, err := (&Header{
		Version:           2,
		Command:           LOCAL,
		TransportProtocol: TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP(testSourceIPv4Addr), Port: 1000},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP(testDestinationIPv4Addr), Port: 2000},
	}).Format()
	if err != nil {
		t.Fatalf("format forged LOCAL header: %v", err)
	}
	return raw
}

// TestCommandPolicyDenyConsumesExactlyHeader pins the deny semantics: the
// denied header is fully parsed — consuming exactly its declared bytes — and
// the application payload that follows stays buffered, unswallowed. The
// denied state is stable: every read returns ErrCommandDenied and the header
// is never exposed.
func TestCommandPolicyDenyConsumesExactlyHeader(t *testing.T) {
	server, client := net.Pipe()
	closeOnCleanup(t, "server connection", server)
	closeOnCleanup(t, "client connection", client)

	conn := NewConn(server, WithCommandPolicy(func(cmd ProtocolVersionAndCommand) CommandPolicy {
		if cmd.IsLocal() {
			return CommandDeny
		}
		return CommandAllow
	}))

	header := []byte("PROXY UNKNOWN\r\n")
	payload := []byte("ping")
	writeErr := make(chan error, 1)
	go func() {
		// A single write: header and payload travel together, so anything
		// consumed past the header would have to come out of the payload.
		_, err := client.Write(append(header, payload...))
		writeErr <- err
	}()

	recv := make([]byte, 4)
	if _, err := conn.Read(recv); !errors.Is(err, ErrCommandDenied) {
		t.Fatalf("expected ErrCommandDenied, got %v", err)
	}
	// The denial is not rolled back or replaced by a second parse.
	if _, err := conn.Read(recv); !errors.Is(err, ErrCommandDenied) {
		t.Fatalf("expected ErrCommandDenied on second read, got %v", err)
	}
	if h := conn.ProxyHeader(); h != nil {
		t.Fatalf("denied header must not be exposed, got %+v", h)
	}
	// Exactly the header was consumed; the payload remains buffered.
	if buffered := conn.bufReader.Buffered(); buffered != len(payload) {
		t.Fatalf("denied header swallowed payload: %d payload bytes remain buffered, want %d", buffered, len(payload))
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write: %v", err)
	}
}

// TestCommandPolicyDeferKeepsRealAddrs pins the defer semantics: the header
// is consumed and exposed via ProxyHeader for inspection, but its addresses
// are never applied — RemoteAddr/LocalAddr keep returning the real connection
// endpoints — and the payload flows normally.
func TestCommandPolicyDeferKeepsRealAddrs(t *testing.T) {
	l := newLocalListener(t)
	pl := &Listener{
		Listener: l,
		CommandPolicy: func(cmd ProtocolVersionAndCommand) CommandPolicy {
			if cmd.IsProxy() {
				return CommandDefer
			}
			return CommandAllow
		},
	}

	cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), header: testTCPv4Header()})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	proxyConn := conn.(*Conn)
	if proxyConn.RemoteAddr().String() != proxyConn.Raw().RemoteAddr().String() {
		t.Fatalf("deferred PROXY header applied its source address: %v", proxyConn.RemoteAddr())
	}
	if proxyConn.LocalAddr().String() != proxyConn.Raw().LocalAddr().String() {
		t.Fatalf("deferred PROXY header applied its destination address: %v", proxyConn.LocalAddr())
	}
	// The deferred header stays available for the application's own decision.
	h := proxyConn.ProxyHeader()
	if h == nil || !h.Command.IsProxy() {
		t.Fatalf("deferred header not exposed via ProxyHeader: %+v", h)
	}
	if h.SourceAddr.String() != "10.1.1.1:1000" {
		t.Fatalf("deferred header lost its inspected addresses: %v", h.SourceAddr)
	}

	recv := make([]byte, 4)
	if _, err := conn.Read(recv); err != nil {
		t.Fatalf("read after deferred header: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("unexpected payload %q", recv)
	}
	expectClientOK(t, cliResult)
}

// TestCommandPolicyDefaultAllowsProxy pins compatibility: with no command
// policy configured, a PROXY header is applied exactly as before.
func TestCommandPolicyDefaultAllowsProxy(t *testing.T) {
	l := newLocalListener(t)
	pl := &Listener{Listener: l}

	cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), header: testTCPv4Header()})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	closeOnCleanup(t, "connection", conn)

	if got := conn.RemoteAddr().String(); got != "10.1.1.1:1000" {
		t.Fatalf("default command policy changed PROXY handling: RemoteAddr = %v", got)
	}
	expectClientOK(t, cliResult)
}

// TestLocalCommandForgedAddressesNotExposed pins the core LOCAL invariant:
// after a LOCAL (v2) or UNKNOWN (v1) header is parsed, the application can
// only observe the listener's own connection endpoints — the forged
// addresses inside the header are discarded during parsing and reachable
// through no API.
func TestLocalCommandForgedAddressesNotExposed(t *testing.T) {
	t.Run("v2 LOCAL with forged TCPv4 block", func(t *testing.T) {
		l := newLocalListener(t)
		pl := &Listener{Listener: l}

		cliResult := make(chan error, 1)
		go func() {
			c, err := net.Dial("tcp", pl.Addr().String())
			if err != nil {
				cliResult <- err
				return
			}
			defer c.Close()
			if _, err := c.Write(append(forgedLocalV2Header(t), []byte("ping")...)); err != nil {
				cliResult <- err
				return
			}
			close(cliResult)
		}()

		conn, err := pl.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		closeOnCleanup(t, "connection", conn)

		proxyConn := conn.(*Conn)
		if proxyConn.RemoteAddr().String() != proxyConn.Raw().RemoteAddr().String() {
			t.Fatalf("LOCAL header leaked a forged remote address: %v", proxyConn.RemoteAddr())
		}
		if proxyConn.LocalAddr().String() != proxyConn.Raw().LocalAddr().String() {
			t.Fatalf("LOCAL header leaked a forged local address: %v", proxyConn.LocalAddr())
		}
		h := proxyConn.ProxyHeader()
		if h == nil || !h.Command.IsLocal() {
			t.Fatalf("expected a parsed LOCAL header, got %+v", h)
		}
		if h.SourceAddr != nil || h.DestinationAddr != nil {
			t.Fatalf("forged addresses survived parsing: src=%v dst=%v", h.SourceAddr, h.DestinationAddr)
		}

		recv := make([]byte, 4)
		if _, err := conn.Read(recv); err != nil {
			t.Fatalf("read after LOCAL header: %v", err)
		}
		if !bytes.Equal(recv, []byte("ping")) {
			t.Fatalf("unexpected payload %q", recv)
		}
		expectClientOK(t, cliResult)
	})

	t.Run("v1 UNKNOWN", func(t *testing.T) {
		l := newLocalListener(t)
		pl := &Listener{Listener: l}

		cliResult := make(chan error, 1)
		go func() {
			c, err := net.Dial("tcp", pl.Addr().String())
			if err != nil {
				cliResult <- err
				return
			}
			defer c.Close()
			if _, err := c.Write([]byte("PROXY UNKNOWN\r\nping")); err != nil {
				cliResult <- err
				return
			}
			close(cliResult)
		}()

		conn, err := pl.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		closeOnCleanup(t, "connection", conn)

		proxyConn := conn.(*Conn)
		if proxyConn.RemoteAddr().String() != proxyConn.Raw().RemoteAddr().String() {
			t.Fatalf("UNKNOWN header leaked a forged remote address: %v", proxyConn.RemoteAddr())
		}
		h := proxyConn.ProxyHeader()
		if h == nil || !h.Command.IsLocal() {
			t.Fatalf("expected v1 UNKNOWN to parse as LOCAL, got %+v", h)
		}
		if h.SourceAddr != nil || h.DestinationAddr != nil {
			t.Fatalf("UNKNOWN header carried addresses: src=%v dst=%v", h.SourceAddr, h.DestinationAddr)
		}
		expectClientOK(t, cliResult)
	})
}

// TestCommandStateStableAcrossReads pins the single-parse invariant: once
// header processing has produced a state for the application, no later bytes
// on the stream — including a second, complete PROXY header — can replace or
// roll back that state. The second header is ordinary payload.
func TestCommandStateStableAcrossReads(t *testing.T) {
	server, client := net.Pipe()
	closeOnCleanup(t, "server connection", server)
	closeOnCleanup(t, "client connection", client)

	conn := NewConn(server)

	header1 := testTCPv4Header()
	raw1, err := header1.Format()
	if err != nil {
		t.Fatalf("format header1: %v", err)
	}
	header2 := &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 9},
	}
	raw2, err := header2.Format()
	if err != nil {
		t.Fatalf("format header2: %v", err)
	}

	go func() {
		_, _ = client.Write(append(raw1, raw2...))
	}()

	// The first read parses header1 and returns header2's bytes as payload.
	recv := make([]byte, len(raw2))
	if _, err := conn.Read(recv); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(recv, raw2) {
		t.Fatalf("second header was not delivered as payload:\n got  %x\n want %x", recv, raw2)
	}

	first := conn.ProxyHeader()
	if first == nil || first.SourceAddr.String() != "10.1.1.1:1000" {
		t.Fatalf("unexpected parsed header: %+v", first)
	}
	if got := conn.RemoteAddr().String(); got != "10.1.1.1:1000" {
		t.Fatalf("RemoteAddr = %v, want 10.1.1.1:1000", got)
	}
	// The second header on the wire neither replaced the parsed state nor
	// rolled the addresses back.
	if again := conn.ProxyHeader(); again != first {
		t.Fatalf("ProxyHeader replaced by a second parse: %+v -> %+v", first, again)
	}
	if got := conn.RemoteAddr().String(); got != "10.1.1.1:1000" {
		t.Fatalf("RemoteAddr changed after the stream moved on: %v", got)
	}
}

// TestCommandPolicyPerCommand exercises independent per-command decisions on
// one listener: LOCAL health checks are denied while PROXY traffic is
// allowed and applied.
func TestCommandPolicyPerCommand(t *testing.T) {
	l := newLocalListener(t)
	pl := &Listener{
		Listener: l,
		CommandPolicy: func(cmd ProtocolVersionAndCommand) CommandPolicy {
			if cmd.IsLocal() {
				return CommandDeny
			}
			return CommandAllow
		},
	}

	// A LOCAL health check is refused with a stable error.
	localClient := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     &Header{Version: 2, Command: LOCAL, TransportProtocol: UNSPEC},
		headerOnly: true,
	})
	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("accept LOCAL: %v", err)
	}
	closeOnCleanup(t, "LOCAL connection", conn)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrCommandDenied) {
		t.Fatalf("expected ErrCommandDenied for LOCAL, got %v", err)
	}
	expectClientOK(t, localClient)

	// A PROXY connection on the same listener is served normally.
	proxyClient := runClient(t, clientConfig{addr: pl.Addr().String(), header: testTCPv4Header()})
	conn, err = pl.Accept()
	if err != nil {
		t.Fatalf("accept PROXY: %v", err)
	}
	closeOnCleanup(t, "PROXY connection", conn)
	if got := conn.RemoteAddr().String(); got != "10.1.1.1:1000" {
		t.Fatalf("PROXY header not applied after a denied LOCAL: RemoteAddr = %v", got)
	}
	recv := make([]byte, 4)
	if _, err := conn.Read(recv); err != nil {
		t.Fatalf("read PROXY payload: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("unexpected payload %q", recv)
	}
	expectClientOK(t, proxyClient)
}

// TestAcceptConcurrentMixedCommands hammers Accept with a mix of forged
// LOCAL and PROXY headers and verifies every connection lands in the state
// its command dictates — PROXY addresses applied, LOCAL connections bound to
// the real endpoints — with no cross-connection leakage. Run with -race.
func TestAcceptConcurrentMixedCommands(t *testing.T) {
	l := newLocalListener(t)
	pl := &Listener{Listener: l}

	const n = 16
	results := make(chan *Conn, n)
	errCh := make(chan error, n)

	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			c, err := pl.Accept()
			if err != nil {
				errCh <- err
				return
			}
			// Force header processing inside the accepting goroutine so parses
			// race with one another.
			_ = c.RemoteAddr()
			results <- c.(*Conn)
		})
	}

	clients := make([]<-chan error, 0, n)
	for i := range n {
		var header *Header
		if i%2 == 0 {
			header = testTCPv4Header() // forged PROXY source 10.1.1.1:1000
		} else {
			header = &Header{ // forged LOCAL carrying a full TCPv4 block
				Version:           2,
				Command:           LOCAL,
				TransportProtocol: TCPv4,
				SourceAddr:        &net.TCPAddr{IP: net.ParseIP(testSourceIPv4Addr), Port: 1000},
				DestinationAddr:   &net.TCPAddr{IP: net.ParseIP(testDestinationIPv4Addr), Port: 2000},
			}
		}
		clients = append(clients, runClient(t, clientConfig{
			addr:       pl.Addr().String(),
			header:     header,
			closeAfter: true,
		}))
	}

	wg.Wait()
	close(results)
	close(errCh)
	for err := range errCh {
		t.Fatalf("accept: %v", err)
	}

	var proxySeen, localSeen int
	for conn := range results {
		closeOnCleanup(t, "connection", conn)
		remote := conn.RemoteAddr().String()
		switch {
		case remote == "10.1.1.1:1000":
			proxySeen++
			if h := conn.ProxyHeader(); h == nil || !h.Command.IsProxy() {
				t.Fatalf("PROXY connection lost its header: %+v", h)
			}
		case strings.HasPrefix(remote, "127.0.0.1:"):
			localSeen++
			h := conn.ProxyHeader()
			if h == nil || !h.Command.IsLocal() {
				t.Fatalf("LOCAL connection has wrong header: %+v", h)
			}
			if h.SourceAddr != nil || h.DestinationAddr != nil {
				t.Fatalf("LOCAL connection kept forged addresses: src=%v dst=%v", h.SourceAddr, h.DestinationAddr)
			}
		default:
			t.Fatalf("connection got an address from neither policy: %v", remote)
		}
	}
	if proxySeen != n/2 || localSeen != n/2 {
		t.Fatalf("command mix mismatch: %d PROXY, %d LOCAL, want %d each", proxySeen, localSeen, n/2)
	}
	for _, cliResult := range clients {
		expectClientOK(t, cliResult)
	}
}

// TestParseErrorCategoriesStable pins the error category for each malformed-
// header class, so applications can rely on errors.Is across releases, and
// verifies the reader is left at a clean boundary (the connection can simply
// be closed; nothing over-read).
func TestParseErrorCategoriesStable(t *testing.T) {
	cases := []struct {
		desc string
		raw  []byte
		want error
	}{
		{"unknown v2 command", v2Header(0x22, byte(UNSPEC), nil), ErrUnsupportedProtocolVersionAndCommand},
		{"undefined v2 address family", v2Header(byte(PROXY), 0x99, nil), ErrUnsupportedAddressFamilyAndProtocol},
		{"v2 truncated length field", append(SIGV2, byte(PROXY), byte(TCPv4)), ErrCantReadLength},
		{"v2 truncated address block", append(append(SIGV2, byte(PROXY), byte(TCPv4)), lengthV4Bytes...), ErrInvalidAddress},
		{"v1 address family mismatch", []byte("PROXY TCP4 ::1 10.0.0.1 1 2\r\n"), ErrInvalidAddress},
		{"v1 unknown transport token", []byte("PROXY SCTP4 1.2.3.4 5.6.7.8 1 2\r\n"), ErrCantReadAddressFamilyAndProtocol},
		{"v1 header too long", []byte("PROXY UNKNOWN " + strings.Repeat("A", 100) + "\r\n"), ErrVersion1HeaderTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := Read(bufio.NewReader(bytes.NewReader(tc.raw)))
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestListenerRecoversAfterCommandError pins cleanup: a connection whose
// header fails parsing returns a stable error and closes cleanly, and the
// listener keeps serving subsequent, well-formed connections.
func TestListenerRecoversAfterCommandError(t *testing.T) {
	l := newLocalListener(t)
	pl := &Listener{Listener: l}

	// Client 1 sends a v2 frame with an unknown command byte.
	badClient := make(chan error, 1)
	go func() {
		c, err := net.Dial("tcp", pl.Addr().String())
		if err != nil {
			badClient <- err
			return
		}
		defer c.Close()
		if _, err := c.Write(v2Header(0x22, byte(UNSPEC), nil)); err != nil {
			badClient <- err
			return
		}
		close(badClient)
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("accept bad client: %v", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrUnsupportedProtocolVersionAndCommand) {
		t.Fatalf("expected ErrUnsupportedProtocolVersionAndCommand, got %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("closing the failed connection: %v", err)
	}
	expectClientOK(t, badClient)

	// Client 2 is served normally on the same listener.
	goodClient := runClient(t, clientConfig{addr: pl.Addr().String(), header: testTCPv4Header()})
	conn, err = pl.Accept()
	if err != nil {
		t.Fatalf("accept good client: %v", err)
	}
	closeOnCleanup(t, "good connection", conn)
	if got := conn.RemoteAddr().String(); got != "10.1.1.1:1000" {
		t.Fatalf("listener did not recover: RemoteAddr = %v", got)
	}
	recv := make([]byte, 4)
	if _, err := conn.Read(recv); err != nil {
		t.Fatalf("read from good client: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("unexpected payload %q", recv)
	}
	expectClientOK(t, goodClient)
}
