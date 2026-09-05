package dnsengine

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestProxy_Integration(t *testing.T) {
	upstreamAddr := "127.0.0.1:53053"
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Name == "google.com." {
			rr, _ := dns.NewRR("google.com. 300 IN A 1.1.1.1")
			msg.Answer = append(msg.Answer, rr)
		}
		_ = w.WriteMsg(msg)
	})
	upstreamServer := &dns.Server{Addr: upstreamAddr, Net: "udp", Handler: mux}
	go func() { _ = upstreamServer.ListenAndServe() }()
	defer func() { _ = upstreamServer.Shutdown() }()
	time.Sleep(100 * time.Millisecond)

	domains := []string{"google.com"}
	pool := NewIPPool(domains, "198.18", "fd00:18::")

	proxyAddr := "127.0.0.1:53054"
	proxy := NewDNSProxy(proxyAddr, upstreamAddr, pool, nil, nil, 300, true)

	go func() { _ = proxy.Start() }()
	defer proxy.Close()
	time.Sleep(100 * time.Millisecond)

	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxyAddr)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answer))
	}

	aRecord, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Expected A record in answer")
	}

	resolvedIP := aRecord.A.String()
	if !strings.HasPrefix(resolvedIP, "198.") {
		t.Errorf("Fake IP replacement failed: expected 198.x.x.x, got %s", resolvedIP)
	}
}

func TestSync_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	sm1 := NewSyncManager("127.0.0.1:53062", "53061", nil, "198.18.0.0/15", "fd00::/106", tmpDir, nil)
	err := sm1.StartServer()
	if err != nil {
		t.Fatalf("Failed to start SyncManager 1: %v", err)
	}
	defer sm1.Close()

	sm2 := NewSyncManager("127.0.0.1:53061", "53062", nil, "198.18.0.0/15", "fd00::/106", tmpDir, nil)
	err = sm2.StartServer()
	if err != nil {
		t.Fatalf("Failed to start SyncManager 2: %v", err)
	}
	defer sm2.Close()

	time.Sleep(1 * time.Second)

	sm1.mu.RLock()
	connsLen := len(sm1.conns)
	sm1.mu.RUnlock()

	if connsLen == 0 {
		sm1.discoverAndConnect()
		sm2.discoverAndConnect()
		time.Sleep(1 * time.Second)
	}

	fakeIP := net.ParseIP("198.18.0.10")
	realIP := net.ParseIP("8.8.8.8")

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		sm1.BroadcastMappings([]Mapping{{FakeIP: fakeIP, RealIP: realIP, Version: 1}})
		time.Sleep(500 * time.Millisecond)
	}()

	wg.Wait()
}

func TestProxy_IPv6Disabled(t *testing.T) {
	upstreamAddr := "127.0.0.1:53055"
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		if len(r.Question) > 0 {
			switch r.Question[0].Qtype {
			case dns.TypeA:
				rr, _ := dns.NewRR("example.com. 300 IN A 1.2.3.4")
				msg.Answer = append(msg.Answer, rr)
			case dns.TypeAAAA:
				rr, _ := dns.NewRR("example.com. 300 IN AAAA 2001:db8::1")
				msg.Answer = append(msg.Answer, rr)
			case dns.TypeHTTPS:
				rr, _ := dns.NewRR("example.com. 300 IN HTTPS 1 . alpn=h2,h3 ipv4hint=1.2.3.4 ipv6hint=2001:db8::1")
				msg.Answer = append(msg.Answer, rr)
			}
		}
		_ = w.WriteMsg(msg)
	})
	upstreamServer := &dns.Server{Addr: upstreamAddr, Net: "udp", Handler: mux}
	go func() { _ = upstreamServer.ListenAndServe() }()
	defer func() { _ = upstreamServer.Shutdown() }()
	time.Sleep(100 * time.Millisecond)

	pool := NewIPPool([]string{"example.com"}, "198.18", "fd00:18::")
	proxyAddr := "127.0.0.1:53056"
	proxy := NewDNSProxy(proxyAddr, upstreamAddr, pool, nil, nil, 300, false)

	go func() { _ = proxy.Start() }()
	defer proxy.Close()
	time.Sleep(100 * time.Millisecond)

	client := new(dns.Client)

	// A query should succeed with Fake IPv4
	msgA := new(dns.Msg)
	msgA.SetQuestion("example.com.", dns.TypeA)
	respA, _, err := client.Exchange(msgA, proxyAddr)
	if err != nil {
		t.Fatalf("A query failed: %v", err)
	}
	if len(respA.Answer) != 1 {
		t.Fatalf("Expected 1 A answer, got %d", len(respA.Answer))
	}
	if !strings.HasPrefix(respA.Answer[0].(*dns.A).A.String(), "198.") {
		t.Fatalf("Expected fake IPv4, got %s", respA.Answer[0].(*dns.A).A.String())
	}

	// AAAA query should return NOERROR with empty answer
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion("example.com.", dns.TypeAAAA)
	respAAAA, _, err := client.Exchange(msgAAAA, proxyAddr)
	if err != nil {
		t.Fatalf("AAAA query failed: %v", err)
	}
	if len(respAAAA.Answer) != 0 {
		t.Fatalf("Expected 0 AAAA answers when IPv6 is disabled, got %d", len(respAAAA.Answer))
	}

	// HTTPS query should strip ipv6hint
	msgHTTPS := new(dns.Msg)
	msgHTTPS.SetQuestion("example.com.", dns.TypeHTTPS)
	respHTTPS, _, err := client.Exchange(msgHTTPS, proxyAddr)
	if err != nil {
		t.Fatalf("HTTPS query failed: %v", err)
	}
	if len(respHTTPS.Answer) != 1 {
		t.Fatalf("Expected 1 HTTPS answer, got %d", len(respHTTPS.Answer))
	}
	httpsRec := respHTTPS.Answer[0].(*dns.HTTPS)
	for _, kv := range httpsRec.Value {
		if kv.Key() == dns.SVCB_IPV6HINT {
			t.Fatalf("Expected SVCB_IPV6HINT to be stripped when IPv6 is disabled")
		}
	}
}
