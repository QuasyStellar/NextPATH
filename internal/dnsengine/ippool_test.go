package dnsengine

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIPPool_CollisionAndMemory(t *testing.T) {
	numDomains := 200000
	domains := make([]string, numDomains)
	for i := 0; i < numDomains; i++ {
		domains[i] = fmt.Sprintf("domain-%d.com", i)
	}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	pool := NewIPPoolWithConfig(domains, "198.18", "fd00:18::", IPPoolConfig{PoolSizeV4: 1048576, PoolSizeV6: 1048576})

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	fmt.Printf("\n--- IPPool STATS ---\n")
	fmt.Printf("IPPool RAM used for 200k domains: %.2f MB\n", float64(m2.Alloc-m1.Alloc)/1024/1024)

	occupiedV4 := make(map[string]string)
	totalMappings := 0

	for i := 0; i < numDomains; i++ {
		domain := domains[i]
		numIPs := (i % 5) + 1
		reals := make([]net.IP, numIPs)
		for j := 0; j < numIPs; j++ {
			reals[j] = net.IPv4(byte(10+(i>>16)), byte(i>>8), byte(i), byte(j))
		}

		fakes, _, ok := pool.GetFakeIPsForReals(reals, false)
		if !ok {
			t.Fatalf("Failed to allocate for %s", domain)
		}

		for realIPStr, fakeIP := range fakes {
			totalMappings++
			fakeIPStr := fakeIP.String()
			key := fmt.Sprintf("%s|%s", domain, realIPStr)
			if existing, exists := occupiedV4[fakeIPStr]; exists {
				t.Fatalf("COLLISION DETECTED: Fake IP %s maps to both %s and %s", fakeIPStr, existing, key)
			}
			occupiedV4[fakeIPStr] = key
		}
	}

	fmt.Printf("IPPool Total allocations: %d (0 collisions guaranteed)\n", totalMappings)
	fmt.Printf("IPPool Subnet Net: %s\n", pool.GetPoolNet())
	fmt.Printf("----------------\n")
}

func TestIPPool_IPv6CollisionAndMemory(t *testing.T) {
	numDomains := 500000
	domains := make([]string, numDomains)
	for i := 0; i < numDomains; i++ {
		domains[i] = fmt.Sprintf("ipv6-domain-%d.com", i)
	}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	pool := NewIPPool(domains, "198.18", "fd00:18::")

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	fmt.Printf("\n--- IPPool IPv6 STATS ---\n")
	fmt.Printf("IPPool RAM used for 500K domains (IPv6): %.2f MB\n", float64(m2.Alloc-m1.Alloc)/1024/1024)

	occupiedV6 := make(map[string]string)
	totalMappings := 0

	for i := 0; i < numDomains; i++ {
		domain := domains[i]
		numIPs := (i % 5) + 1
		reals := make([]net.IP, numIPs)
		for j := 0; j < numIPs; j++ {
			reals[j] = net.ParseIP(fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff))
		}

		fakes, _, ok := pool.GetFakeIPsForReals(reals, true)
		if !ok {
			t.Fatalf("Failed to allocate IPv6 for %s", domain)
		}

		for realIPStr, fakeIP := range fakes {
			totalMappings++
			fakeIPStr := fakeIP.String()
			key := fmt.Sprintf("%s|%s", domain, realIPStr)

			if !strings.HasPrefix(fakeIPStr, "fd00:18:") {
				t.Fatalf("Invalid IPv6 Fake IP prefix: %s (domain: %s)", fakeIPStr, domain)
			}

			if existing, exists := occupiedV6[fakeIPStr]; exists {
				t.Fatalf("IPv6 COLLISION DETECTED: Fake IP %s maps to both %s and %s", fakeIPStr, existing, key)
			}
			occupiedV6[fakeIPStr] = key
		}
	}

	fmt.Printf("IPPool IPv6 Total allocations: %d (0 collisions guaranteed)\n", totalMappings)
	fmt.Printf("-------------------------\n")
}

func TestIPPool_EmptyDomains(t *testing.T) {

	pool := NewIPPoolWithConfig(nil, "198.18", "fd00:18::", IPPoolConfig{
		PoolSizeV4: 1024,
		PoolSizeV6: 65536,
	})

	reals := []net.IP{net.ParseIP("1.1.1.1")}
	fakes, _, ok := pool.GetFakeIPsForReals(reals, false)
	if !ok {
		t.Fatalf("Expected GetFakeIPsForReals to succeed for empty domain list")
	}

	fakeIP, exists := fakes["1.1.1.1"]
	if !exists {
		t.Fatalf("Expected fake IP mapping for 1.1.1.1 to be created")
	}

	if !strings.HasPrefix(fakeIP.String(), "198.18.") {
		t.Errorf("Expected fake IP to be in 198.18.0.0/16 subnet, got %s", fakeIP.String())
	}
}

func TestIPPool_TTLRefresh(t *testing.T) {
	importTime := time.Now()

	pool := NewIPPool([]string{"test.com"}, "198.18", "fd00:18::")
	reals := []net.IP{net.ParseIP("2.2.2.2")}

	_, _, ok := pool.GetFakeIPsForReals(reals, false)
	if !ok {
		t.Fatalf("Failed initial allocation")
	}

	realKey := ToIPKey(reals[0])
	shard := pool.getShard(reals[0])

	shard.mu.RLock()
	expiry1 := shard.expiries[realKey]
	shard.mu.RUnlock()

	if expiry1.Sub(importTime) < 119*time.Minute {
		t.Fatalf("Expected initial expiry to be ~2 hours, got %v", expiry1.Sub(importTime))
	}

	simulatedExpiry := time.Now().Add(4 * time.Minute)
	shard.mu.Lock()
	shard.expiries[realKey] = simulatedExpiry
	shard.mu.Unlock()

	_, _, ok = pool.GetFakeIPsForReals(reals, false)
	if !ok {
		t.Fatalf("Failed second allocation")
	}

	shard.mu.RLock()
	expiry2 := shard.expiries[realKey]
	shard.mu.RUnlock()

	if expiry2.Equal(simulatedExpiry) {
		t.Fatalf("TTL was NOT refreshed! Expiry is still %v", expiry2)
	}
	if time.Until(expiry2) < 119*time.Minute {
		t.Fatalf("TTL was not fully refreshed, got %v", time.Until(expiry2))
	}
}

func TestIPPool_SplitBrainTieBreaker(t *testing.T) {
	pool := NewIPPool(nil, "198.18", "fd00:18::")
	fakeIP := net.ParseIP("198.18.0.5")
	realIP1 := net.ParseIP("1.1.1.1")
	realIP2 := net.ParseIP("2.2.2.2")

	now := time.Now()
	version := uint64(100)

	pool.AddMapping(realIP2, fakeIP, version, now.Add(1*time.Hour))
	pool.AddMapping(realIP1, fakeIP, version, now.Add(1*time.Hour))

	pool.globalMu.Lock()
	realKey := pool.globalFakeToReal[ToIPKey(fakeIP)]
	pool.globalMu.Unlock()

	if !realKey.ToIP().Equal(realIP2) {
		t.Errorf("Expected 2.2.2.2 to win the tie-breaker, got %v", realKey.ToIP())
	}
}

func TestIPPool_Concurrency(t *testing.T) {
	numDomains := 50000
	domains := make([]string, numDomains)
	for i := 0; i < numDomains; i++ {
		domains[i] = fmt.Sprintf("concur-%d.com", i)
	}

	pool := NewIPPool(domains, "198.18", "fd00:18::")

	var wg sync.WaitGroup
	numWorkers := 10
	queriesPerWorker := 10000

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < queriesPerWorker; i++ {
				idx := (workerID*queriesPerWorker + i) % numDomains
				domain := fmt.Sprintf("sub.concur-%d.com", idx)
				reals := []net.IP{net.IPv4(8, 8, byte(workerID), byte(i))}

				fakes, _, ok := pool.GetFakeIPsForReals(reals, false)
				if !ok {
					t.Errorf("Concurrency failure: domain %s rejected", domain)
					return
				}
				if len(fakes) != 1 {
					t.Errorf("Expected 1 mapped IP")
					return
				}
			}
		}(w)
	}

	wg.Wait()
}
func TestIPPool_IPv6Allocation(t *testing.T) {
	domains := []string{"ipv6test.com"}
	pool := NewIPPool(domains, "198.18", "fd00:18::")

	reals := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::2"),
	}

	fakes, _, ok := pool.GetFakeIPsForReals(reals, true)
	if !ok {
		t.Fatalf("IPv6 allocation failed")
	}

	if len(fakes) != 2 {
		t.Fatalf("Expected 2 fake IPv6 addresses, got %d", len(fakes))
	}

	for realStr, fakeIP := range fakes {
		if !strings.HasPrefix(fakeIP.String(), "fd00:18:") {
			t.Errorf("IPv6 Fake IP %s is not in configured subnet fd00:18::/48 (real: %s)", fakeIP.String(), realStr)
		}
	}
}
func TestIPPool_ReloadPerformance(t *testing.T) {
	numDomains := 100000
	domains := make([]string, numDomains)
	for i := 0; i < numDomains; i++ {
		domains[i] = fmt.Sprintf("domain-%d.com", i)
	}
	pool1 := NewIPPool(domains, "198.18", "fd00:18::")

	fakes1, _, ok := pool1.GetFakeIPsForReals([]net.IP{net.ParseIP("1.1.1.1")}, false)
	if !ok {
		t.Fatalf("Query failed in pool1")
	}

	newDomains := make([]string, numDomains)
	for i := 0; i < numDomains; i++ {
		newDomains[i] = fmt.Sprintf("domain-%d.com", i+10000)
	}

	pool2 := NewIPPool(newDomains, "198.18", "fd00:18::")

	fakes2, _, ok := pool2.GetFakeIPsForReals([]net.IP{net.ParseIP("1.1.1.1")}, false)
	if !ok {
		t.Errorf("New domain domain-105000.com was not accepted by the reloaded pool")
	}

	_ = fakes1
	_ = fakes2
}

func BenchmarkIPPool_GetFakeIPsForReals(b *testing.B) {
	pool := NewIPPool(nil, "198.18", "fd00:18::")
	reals := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8"), net.ParseIP("9.9.9.9")}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.GetFakeIPsForReals(reals, false)
		}
	})
}
func TestIPPool_ChaosReload(t *testing.T) {
	domains := []string{"initial.com", "google.com", "yandex.ru"}
	var poolHolder atomic.Pointer[IPPool]
	poolHolder.Store(NewIPPool(domains, "198.18", "fd00:18::"))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	numReaders := 8
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					currentPool := poolHolder.Load()
					reals := []net.IP{net.IPv4(8, 8, 8, byte(readerID))}
					_, _, _ = currentPool.GetFakeIPsForReals(reals, false)
					i++
				}
			}
		}(r)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		reloadCount := 0

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				newDomains := []string{"google.com", "yandex.ru"}
				for i := 0; i < 5000; i++ {
					newDomains = append(newDomains, fmt.Sprintf("reload-%d-domain-%d.com", reloadCount, i))
				}
				newPool := NewIPPool(newDomains, "198.18", "fd00:18::")
				poolHolder.Store(newPool)
				reloadCount++
			}
		}
	}()

	wg.Wait()
}

func TestIPPool_PoolExhaustion(t *testing.T) {
	numDomains := 5000
	domains := make([]string, numDomains)
	for i := 0; i < numDomains; i++ {
		domains[i] = fmt.Sprintf("exhaust-%d.com", i)
	}

	pool := NewIPPool(domains, "198.18.0.0", "fd00:18::")

	for i := 0; i < numDomains; i++ {
		reals := []net.IP{net.IPv4(1, 1, 1, byte(i))}
		_, _, ok := pool.GetFakeIPsForReals(reals, false)
		if !ok {
			t.Fatalf("Exhaustion query failed on index %d", i)
		}
	}
}

func TestAddMapping_ReturnsFalseOnStaleVersion(t *testing.T) {
	pool := NewIPPool(nil, "198.18", "fd00:18::")
	defer pool.Close()

	fakeIP := net.ParseIP("198.18.0.5")
	realFresh := net.ParseIP("1.1.1.1")
	realStale := net.ParseIP("2.2.2.2")
	now := time.Now()

	if !pool.AddMapping(realFresh, fakeIP, 200, now.Add(time.Hour)) {
		t.Fatalf("fresh mapping should be accepted")
	}
	if pool.AddMapping(realStale, fakeIP, 100, now.Add(time.Hour)) {
		t.Fatalf("stale (older-version) mapping should be rejected")
	}

	pool.globalMu.Lock()
	got := pool.globalFakeToReal[ToIPKey(fakeIP)]
	pool.globalMu.Unlock()
	if !got.ToIP().Equal(realFresh) {
		t.Fatalf("pool must still hold fresh mapping, got %v", got.ToIP())
	}
}

func TestAddMapping_ReturnsTrueOnAcceptedUpdate(t *testing.T) {
	pool := NewIPPool(nil, "198.18", "fd00:18::")
	defer pool.Close()

	fakeIP := net.ParseIP("198.18.0.5")
	realOld := net.ParseIP("1.1.1.1")
	realNew := net.ParseIP("2.2.2.2")
	now := time.Now()

	if !pool.AddMapping(realOld, fakeIP, 100, now.Add(time.Hour)) {
		t.Fatalf("initial mapping should be accepted")
	}
	if !pool.AddMapping(realNew, fakeIP, 200, now.Add(time.Hour)) {
		t.Fatalf("higher-versioned update should be accepted")
	}

	pool.globalMu.Lock()
	got := pool.globalFakeToReal[ToIPKey(fakeIP)]
	pool.globalMu.Unlock()
	if !got.ToIP().Equal(realNew) {
		t.Fatalf("pool must reflect newer mapping, got %v", got.ToIP())
	}
}

func TestFakeIPStaysWithinAdvertisedSubnet(t *testing.T) {
	pool := NewIPPoolWithConfig(nil, "198.18.0.0", "fd00:18::",
		IPPoolConfig{PoolSizeV4: 5000, PoolSizeV6: DefaultPoolSizeV6})
	defer pool.Close()

	_, poolNet, err := net.ParseCIDR(pool.GetPoolNet())
	if err != nil {
		t.Fatalf("bad pool net %q: %v", pool.GetPoolNet(), err)
	}

	for i := 0; i < 5000; i++ {
		real := net.IPv4(byte(10+i>>16), byte(i>>8), byte(i), 1)
		fake := pool.ComputeLevel1Hash(real, false)
		if !poolNet.Contains(fake) {
			t.Fatalf("fake IP %v escaped advertised subnet %v (real=%v)", fake, poolNet, real)
		}
	}
}
