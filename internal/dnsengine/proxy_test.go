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
	proxy := NewDNSProxy(proxyAddr, upstreamAddr, pool, nil, nil, 300)

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
