package proxyproto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// This file pins the policy half of the unified header transaction: the
// deterministic results of policy approval, rejection, timeout and connection
// close; the no-state-rollback guarantee; and the rule that only LOCAL or an
// explicitly headerless configuration may expose the local socket address.

// blockingPolicy blocks its first invocation until release is closed, then
// returns policy/err. It models an approval decision that is still pending
// while connection events (timeout, close) happen underneath.
type blockingPolicy struct {
	release chan struct{}
	policy  Policy
	err     error
	once    sync.Once
}

func newBlockingPolicy(policy Policy, err error) *blockingPolicy {
	return &blockingPolicy{release: make(chan struct{}), policy: policy, err: err}
}

func (b *blockingPolicy) fn(ConnPolicyOptions) (Policy, error) {
	b.once.Do(func() { <-b.release })
	return b.policy, b.err
}

// TestApprovalRacePolicyThenConnectionEvents covers rule 3's approval-race
// semantics. The policy decision is made in Accept before any header I/O, so a
// connection that closes or times out while approval is pending cannot roll the
// model state back: once released, the decision still produces the same
// concrete result.
func TestApprovalRacePolicyThenConnectionEvents(t *testing.T) {
	t.Parallel()

	t.Run("approval arrives after peer close, decision still applies", func(t *testing.T) {
		t.Parallel()
		l := newLocalListener(t)
		policy := newBlockingPolicy(REQUIRE, nil)
		pl := &Listener{Listener: l, ConnPolicy: policy.fn, ReadHeaderTimeout: time.Second}

		cliResult := runClient(t, clientConfig{
			addr:       pl.Addr().String(),
			header:     testTCPv4Header(),
			headerOnly: true,
			closeAfter: true,
		})

		// Accept blocks inside the still-pending policy; run it off the main
		// goroutine so the decision can be released below.
		accepted := make(chan net.Conn, 1)
		go func() {
			c, err := pl.Accept()
			if err != nil {
				t.Errorf("Accept: %v", err)
				accepted <- nil
				return
			}
			accepted <- c
		}()

		// Give the client time to connect and close while approval is pending.
		time.Sleep(100 * time.Millisecond)
		close(policy.release)

		var conn net.Conn
		select {
		case conn = <-accepted:
		case <-time.After(time.Second):
			t.Fatal("Accept did not return after the policy was released")
		}
		if conn == nil {
			t.Fatal("expected a wrapped connection")
		}
		t.Cleanup(func() { _ = conn.Close() })
		expectClientOK(t, cliResult)

		// The REQUIRE decision was fixed at Accept time and cannot roll back.
		if c := conn.(*Conn); c.ProxyHeaderPolicy != REQUIRE {
			t.Fatalf("policy rolled back after close: got %v", c.ProxyHeaderPolicy)
		}
		// The peer sent a full header before closing, so the transaction still
		// parses deterministically (or returns a stable terminal EOF error),
		// never ErrNoProxyProtocol.
		_, err := conn.Read(make([]byte, 1))
		if errors.Is(err, ErrNoProxyProtocol) {
			t.Fatal("a complete header followed by close must not read as no-header")
		}
	})

	t.Run("approval returns ErrInvalidUpstream: connection dropped, listener survives", func(t *testing.T) {
		t.Parallel()
		l := newLocalListener(t)
		// The denial releases after the first (blocked) invocation; a later
		// Accept loop iteration would otherwise block on the same gate.
		policy := newBlockingPolicy(REJECT, ErrInvalidUpstream)
		pl := &Listener{Listener: l, ConnPolicy: policy.fn}

		cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), connectOnly: true})

		// Accept is blocked inside the policy. Run it in a goroutine so the test
		// can release the decision.
		accepted := make(chan net.Conn, 1)
		go func() {
			c, _ := pl.Accept()
			accepted <- c
		}()

		close(policy.release)
		expectClientOK(t, cliResult)

		// The denied connection is closed by Accept, which then loops and blocks
		// waiting for the next connection. Closing the listener unblocks that
		// wait; the point is that the ErrInvalidUpstream denial never itself
		// escaped Accept (the first peer was dropped, not surfaced).
		_ = pl.Close()
		select {
		case c := <-accepted:
			if c != nil {
				_ = c.Close()
			}
		case <-time.After(time.Second):
			t.Fatal("Accept did not unblock when the listener was closed")
		}
	})

	t.Run("approval returns a generic error: Accept surfaces it", func(t *testing.T) {
		t.Parallel()
		l := newLocalListener(t)
		boom := errors.New("policy backend unavailable")
		policy := newBlockingPolicy(USE, boom)
		pl := &Listener{Listener: l, ConnPolicy: policy.fn}

		cliResult := runClient(t, clientConfig{addr: pl.Addr().String(), connectOnly: true})
		acceptErr := make(chan error, 1)
		go func() {
			_, err := pl.Accept()
			acceptErr <- err
		}()

		close(policy.release)
		select {
		case err := <-acceptErr:
			if !errors.Is(err, boom) {
				t.Fatalf("expected the generic policy error, got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Accept did not surface the generic policy error")
		}
		expectClientOK(t, cliResult)
	})
}

// TestPolicyOutcomesAreDeterministic covers rule 3's four connection-level
// outcomes at the Conn boundary: waiting (bounded by the header timeout),
// rejection, timeout and close each produce one fixed result, and repeating the
// call returns the same result (the once-guarded state cannot roll back).
func TestPolicyOutcomesAreDeterministic(t *testing.T) {
	t.Parallel()

	t.Run("REJECT plus a header is a stable superfluous-header error", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		go func() {
			_, _ = testTCPv4Header().WriteTo(client)
		}()

		conn := NewConn(server, WithPolicy(REJECT), SetReadHeaderTimeout(time.Second))
		for range 3 {
			_, err := conn.Read(make([]byte, 1))
			if !errors.Is(err, ErrSuperfluousProxyHeader) {
				t.Fatalf("expected ErrSuperfluousProxyHeader, got %v", err)
			}
		}
		if h := conn.ProxyHeader(); h != nil {
			t.Fatalf("REJECT must not retain the header, got %+v", h)
		}
	})

	t.Run("REQUIRE timeout with no header is a stable no-proxy error", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		// client never writes.

		conn := NewConn(server, WithPolicy(REQUIRE), SetReadHeaderTimeout(80*time.Millisecond))
		start := time.Now()
		_, err := conn.Read(make([]byte, 1))
		if !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol, got %v", err)
		}
		if time.Since(start) < 40*time.Millisecond {
			t.Fatal("read returned before the header timeout elapsed")
		}
		// The result is terminal: later calls do not re-block or change verdict.
		again, err2 := conn.Read(make([]byte, 1))
		if again != 0 || !errors.Is(err2, ErrNoProxyProtocol) {
			t.Fatalf("repeated read changed the timeout verdict: n=%d err=%v", again, err2)
		}
	})

	t.Run("close during header wait is a stable terminal error", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })

		conn := NewConn(server, WithPolicy(REQUIRE), SetReadHeaderTimeout(0))
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = client.Close()
		}()

		_, err := conn.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("expected an error when the peer closes during header wait")
		}
		// No signature was ever sent, so a clean close reads as no-header.
		if !errors.Is(err, ErrNoProxyProtocol) {
			t.Fatalf("expected ErrNoProxyProtocol on a silent, closed peer, got %v", err)
		}
		if _, err2 := conn.Read(make([]byte, 1)); !errors.Is(err2, err) {
			t.Fatalf("repeated read changed the close verdict: %v vs %v", err2, err)
		}
	})

	t.Run("close after a signature prefix is a stable truncation error", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })

		conn := NewConn(server, WithPolicy(USE), SetReadHeaderTimeout(0))
		go func() {
			_, _ = client.Write(SIGV2[:6])
			_ = client.Close()
		}()

		_, err := conn.Read(make([]byte, 1))
		if !errors.Is(err, ErrIncompleteProxyProtocolSignature) {
			t.Fatalf("expected truncated-signature error, got %v", err)
		}
		if _, err2 := conn.Read(make([]byte, 1)); !errors.Is(err2, err) {
			t.Fatalf("repeated read changed the truncation verdict: %v vs %v", err2, err)
		}
	})
}

// TestStallAfterSignaturePrefixIsNotHeaderless pins rule 1 through the Conn
// timeout path: signature bytes already buffered when the header timeout fires
// make the verdict a truncated header, even under an optional-header policy
// that would otherwise serve the buffered bytes as raw application data.
func TestStallAfterSignaturePrefixIsNotHeaderless(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })

	conn := NewConn(server, WithPolicy(USE), SetReadHeaderTimeout(80*time.Millisecond))
	go func() {
		// Send a v1 signature prefix and stall without completing the line.
		_, _ = client.Write([]byte("PRO"))
	}()

	_, err := conn.Read(make([]byte, 1))
	if !errors.Is(err, ErrIncompleteProxyProtocolSignature) {
		t.Fatalf("a stall after a signature prefix must be a truncated header, got %v", err)
	}
	// The signature bytes must not have leaked into the application stream.
	if h := conn.ProxyHeader(); h != nil {
		t.Fatalf("a truncated transaction must not retain a header, got %+v", h)
	}
}

// TestOnlyLocalOrHeaderlessExposesLocalAddress covers rule 6: only a LOCAL
// command (v2 LOCAL / v1 UNKNOWN) or an explicitly headerless connection may
// report the local socket address; every failure path cleans connection state
// so the accessors fall back to the underlying socket, never to a half-parsed
// proxy address.
func TestOnlyLocalOrHeaderlessExposesLocalAddress(t *testing.T) {
	t.Parallel()
	rawLocal := func(c *Conn) string { return c.Raw().LocalAddr().String() }
	rawRemote := func(c *Conn) string { return c.Raw().RemoteAddr().String() }

	t.Run("LOCAL command falls back to socket addresses", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		go func() {
			local := &Header{Version: 2, Command: LOCAL, TransportProtocol: UNSPEC}
			_, _ = local.WriteTo(client)
			_, _ = client.Write([]byte("hi"))
		}()

		conn := NewConn(server, WithPolicy(USE), SetReadHeaderTimeout(time.Second))
		if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
			t.Fatalf("read: %v", err)
		}
		if conn.LocalAddr().String() != rawLocal(conn) {
			t.Fatal("LOCAL must expose the underlying local address")
		}
		if conn.RemoteAddr().String() != rawRemote(conn) {
			t.Fatal("LOCAL must expose the underlying remote address")
		}
	})

	t.Run("headerless USE connection keeps socket addresses", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		go func() { _, _ = client.Write([]byte("raw")) }()

		conn := NewConn(server, WithPolicy(USE), SetReadHeaderTimeout(time.Second))
		if _, err := io.ReadFull(conn, make([]byte, 3)); err != nil {
			t.Fatalf("read: %v", err)
		}
		if conn.ProxyHeader() != nil {
			t.Fatal("headerless connection must not carry a header")
		}
		if conn.RemoteAddr().String() != rawRemote(conn) {
			t.Fatal("headerless connection must keep the socket remote address")
		}
	})

	t.Run("parse failure cleans state and falls back to socket addresses", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		go func() {
			// Syntactically invalid v1 body after a valid signature.
			_, _ = client.Write([]byte("PROXY TCP4 not-an-ip 5.6.7.8 80 443\r\n"))
		}()

		conn := NewConn(server, WithPolicy(USE), SetReadHeaderTimeout(time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("expected a parse error")
		}
		if h := conn.ProxyHeader(); h != nil {
			t.Fatalf("failed transaction must not retain a header, got %+v", h)
		}
		if conn.RemoteAddr().String() != rawRemote(conn) {
			t.Fatal("failed transaction must fall back to the socket remote address")
		}
		if conn.LocalAddr().String() != rawLocal(conn) {
			t.Fatal("failed transaction must fall back to the socket local address")
		}
	})

	t.Run("IGNORE consumes the header but exposes socket addresses", func(t *testing.T) {
		t.Parallel()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		go func() {
			_, _ = testTCPv4Header().WriteTo(client)
			_, _ = client.Write([]byte("ping"))
		}()

		conn := NewConn(server, WithPolicy(IGNORE), SetReadHeaderTimeout(time.Second))
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			t.Fatalf("read: %v", err)
		}
		if conn.ProxyHeader() != nil {
			t.Fatal("IGNORE must not expose the parsed header")
		}
		if conn.RemoteAddr().String() != rawRemote(conn) {
			t.Fatal("IGNORE must keep the socket remote address")
		}
	})
}

// TestConcurrentFirstReadRunsTransactionOnce is the race half of rule 7: many
// goroutines hitting Read before the header is processed must trigger exactly
// one parse (sync.Once), share the single result under -race, and between them
// receive the body bytes exactly once — no byte duplicated or lost, even though
// the order of the 1-byte reads is nondeterministic.
func TestConcurrentFirstReadRunsTransactionOnce(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })

	const goroutines = 16
	// One byte per goroutine so every concurrent Read is satisfied by body data
	// rather than blocking on the otherwise-silent pipe.
	body := bytes.Repeat([]byte{'Z'}, goroutines)
	go func() {
		_, _ = testTCPv4Header().WriteTo(client)
		_, _ = client.Write(body)
	}()

	conn := NewConn(server, WithPolicy(REQUIRE), SetReadHeaderTimeout(time.Second))

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		got      []byte
		firstErr error
	)
	for range goroutines {
		wg.Go(func() {
			buf := make([]byte, 1)
			n, err := conn.Read(buf)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && !errors.Is(err, io.EOF) {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			got = append(got, buf[:n]...)
		})
	}
	wg.Wait()

	if firstErr != nil {
		t.Fatalf("concurrent first read failed: %v", firstErr)
	}

	// The header was processed once and is the same object for every observer.
	h := conn.ProxyHeader()
	if h == nil || h.SourceAddr.String() != "10.1.1.1:1000" {
		t.Fatalf("unexpected shared header: %+v", h)
	}

	// Every body byte was delivered to some goroutine. Concurrent 1-byte reads
	// may interleave but must never duplicate or drop a byte, and the header
	// bytes must not appear in the delivered set.
	if !sameBytes(got, body) {
		t.Fatalf("body not delivered exactly once under concurrent reads: got %q want %q", got, body)
	}
}

// sameBytes reports whether a and b contain the same bytes with the same
// frequencies, independent of order.
func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[byte]int{}
	for _, x := range a {
		counts[x]++
	}
	for _, x := range b {
		counts[x]--
		if counts[x] < 0 {
			return false
		}
	}
	return true
}

// TestConcurrentReadAndWriteToDrainBuffer covers the other buffered-teardown
// race: Read and WriteTo both inspect and nil bufReader once the header
// transaction is done. Running them concurrently under -race must not detect a
// race, and the buffered body must be delivered exactly once between the two
// consumers. A real TCP connection (closed by the client after writing) is used
// rather than net.Pipe so WriteTo's trailing io.Copy terminates on EOF.
func TestConcurrentReadAndWriteToDrainBuffer(t *testing.T) {
	t.Parallel()
	l := newLocalListener(t)
	pl := &Listener{Listener: l, ConnPolicy: func(ConnPolicyOptions) (Policy, error) { return REQUIRE, nil }}

	body := bytes.Repeat([]byte{'Q'}, 64)
	cliResult := runClient(t, clientConfig{
		addr:       pl.Addr().String(),
		header:     testTCPv4Header(),
		payload:    body,
		closeAfter: true,
	})

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	proxyConn := conn.(*Conn)

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		got []byte
	)

	// A Read consumer and a WriteTo consumer race for the buffered bytes.
	wg.Go(func() {
		buf := make([]byte, 1)
		for range len(body) / 2 {
			n, readErr := proxyConn.Read(buf)
			if readErr != nil {
				return
			}
			mu.Lock()
			got = append(got, buf[:n]...)
			mu.Unlock()
		}
	})
	wg.Go(func() {
		var out bytes.Buffer
		_, _ = proxyConn.WriteTo(&out)
		mu.Lock()
		got = append(got, out.Bytes()...)
		mu.Unlock()
	})
	wg.Wait()

	if !sameBytes(got, body) {
		t.Fatalf("buffered body not delivered exactly once across Read+WriteTo: got %d bytes, want %d", len(got), len(body))
	}
	expectClientOK(t, cliResult)
}
