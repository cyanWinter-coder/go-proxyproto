// Package main is a runnable UDP server that receives PROXY protocol datagrams
// through a net.PacketConn.
//
// NewUDPPacketConn turns the wrapped socket into a net.PacketConn that consumes
// exactly one PROXY header per datagram and returns the proxied payload. ReadFrom
// reports the client address carried by the header (or the relaying proxy for
// LOCAL datagrams), and WriteTo routes a reply back through the proxy that
// relayed for that client, so the echo loop below looks like plain UDP code.
package main

import (
	"errors"
	"log"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

func main() {
	// A plain UDP socket: the PROXY header travels in every datagram, so no
	// connection state exists between reads. The literal 127.0.0.1 matches the
	// client in examples/udpclient; "localhost" may resolve to ::1 and leave
	// the pair on different loopback sockets.
	addr := "127.0.0.1:9877"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("couldn't resolve %q: %q\n", addr, err.Error())
	}
	inner, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("couldn't listen to %q: %q\n", addr, err.Error())
	}

	// The flow table that maps a header-declared client address back to the
	// proxy that relayed for it is bounded by MaxFlows (oldest entry evicted
	// first). DropHook sees every datagram that carried no complete valid
	// header; the address passed to it is the real socket peer, so it is also
	// where a trusted-source check belongs.
	server := proxyproto.NewUDPPacketConn(inner, proxyproto.UDPPacketConnOptions{
		MaxFlows: 1024,
		DropHook: func(remote net.Addr, err error) {
			if errors.Is(err, proxyproto.ErrDatagramTruncated) {
				log.Printf("dropping truncated datagram from %q: %v", remote, err)
				return
			}
			log.Printf("dropping datagram from %q: %v", remote, err)
		},
	})
	defer func() {
		if err := server.Close(); err != nil {
			log.Printf("failed to close server: %v", err)
		}
	}()

	log.Printf("listening on %q (PROXY protocol over UDP)", server.LocalAddr())

	buf := make([]byte, 65535)
	for {
		// ReadFrom returns one datagram's payload and the client address. A
		// datagram without a complete, valid header is dropped by the wrapper
		// and never surfaces as raw payload.
		n, clientAddr, err := server.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("failed to read datagram: %v", err)
			continue
		}

		// clientAddr is the original client carried by the header; the reply
		// goes back through the relaying proxy, not directly to the client.
		log.Printf("payload %q from client %q", buf[:n], clientAddr)
		if _, err := server.WriteTo(buf[:n], clientAddr); err != nil {
			log.Printf("reply failed: %v", err)
		}
	}
}

// The wrapper is a net.PacketConn, so it can replace the raw socket anywhere
// the application already accepts one.
var _ net.PacketConn = (*proxyproto.UDPPacketConn)(nil)
