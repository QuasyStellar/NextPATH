package netlink

import (
	"net"
	"testing"
	"time"
)

func TestNFTables_Integration(t *testing.T) {

	err := InitStructure("100.64.0.0/16", "fd00:18::/112")
	if err != nil {
		t.Skipf("Skipping test, nftables initialization failed (probably missing NET_ADMIN): %v", err)
	}

	client, err := NewNFTClient()
	if err != nil {
		t.Fatalf("Failed to create NFTClient: %v", err)
	}
	defer client.Close()

	fakeIPv4 := net.ParseIP("100.64.221.77")
	realIPv4 := net.ParseIP("1.2.3.4")

	fakeIPv6 := net.ParseIP("fd00:18::221:77")
	realIPv6 := net.ParseIP("2001:db8::1")

	err = client.AddMapping(fakeIPv4, realIPv4, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to add IPv4 mapping: %v", err)
	}

	err = client.AddMapping(fakeIPv6, realIPv6, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to add IPv6 mapping: %v", err)
	}

	time.Sleep(2 * time.Second)

	mappings, err := client.ReadExistingMappings()
	if err != nil {
		t.Fatalf("Failed to read existing mappings: %v", err)
	}

	if len(mappings) < 2 {
		t.Fatalf("Expected at least 2 mappings, got %d", len(mappings))
	}

	v4Rec, ok := mappings[fakeIPv4.String()]
	if !ok {
		t.Fatalf("IPv4 mapping %s not found in recovery", fakeIPv4.String())
	}
	if !v4Rec.RealIP.Equal(realIPv4) {
		t.Errorf("IPv4 recovered RealIP mismatch: expected %v, got %v", realIPv4, v4Rec.RealIP)
	}
	if v4Rec.Expires > 8*time.Second {
		t.Errorf("IPv4 recovered Expires should be <= 8s, got: %v", v4Rec.Expires)
	}

	conn, _ := net.DialTimeout("tcp", fakeIPv4.String()+":80", 50*time.Millisecond)
	if conn != nil {
		conn.Close()
	}

	time.Sleep(100 * time.Millisecond)

	mappingsRefreshed, err := client.ReadExistingMappings()
	if err != nil {
		t.Fatalf("Failed to read existing mappings: %v", err)
	}

	v4RecRefreshed := mappingsRefreshed[fakeIPv4.String()]
	if v4RecRefreshed.Expires < 9*time.Second {
		t.Errorf("IPv4 recovered Expires should have been refreshed to ~10s, got: %v", v4RecRefreshed.Expires)
	}
}
