package dnsengine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"nextpath/internal/logger"
	"sort"
	"strings"
	"sync"
	"time"
)

type MappingInfo struct {
	IP      net.IP
	Version uint64
}

const (
	DefaultPoolSizeV4 = 131072
	DefaultPoolSizeV6 = 1048576
	MinPoolSize       = 1024
	MappingTTL        = 2 * time.Hour
)

type IPPoolConfig struct {
	PoolSizeV4 uint32
	PoolSizeV6 uint32
}

type IPKey struct {
	isIPv6 bool
	v4     uint32
	v6     [16]byte
}

func ToIPKey(ip net.IP) IPKey {
	ip4 := ip.To4()
	if ip4 != nil {
		return IPKey{
			isIPv6: false,
			v4:     binary.BigEndian.Uint32(ip4),
		}
	}
	var v6 [16]byte
	copy(v6[:], ip.To16())
	return IPKey{
		isIPv6: true,
		v6:     v6,
	}
}

func (k IPKey) ToIP() net.IP {
	if !k.isIPv6 {
		return net.IPv4(byte(k.v4>>24), byte(k.v4>>16), byte(k.v4>>8), byte(k.v4))
	}
	return net.IP(k.v6[:])
}

type cacheShard struct {
	mu         sync.RWMutex
	realToFake map[IPKey]IPKey
	expiries   map[IPKey]time.Time
}

type IPPool struct {
	shards           [64]*cacheShard
	globalMu         sync.Mutex
	globalFakeToReal map[IPKey]IPKey
	globalVersions   map[IPKey]uint64
	poolStart        uint32
	poolSize         uint32
	cidrMask         int
	poolStart6       []byte
	poolSize6        uint32
	cidrMask6        int

	stopCh chan struct{}
	hlc    uint64
	hlcMu  sync.Mutex
}

func NewIPPool(domains []string, baseSubnetV4 string, baseSubnetV6 string) *IPPool {
	return NewIPPoolWithConfig(domains, baseSubnetV4, baseSubnetV6, IPPoolConfig{
		PoolSizeV4: DefaultPoolSizeV4,
		PoolSizeV6: DefaultPoolSizeV6,
	})
}

func NewIPPoolWithConfig(domains []string, baseSubnetV4 string, baseSubnetV6 string, cfg IPPoolConfig) *IPPool {

	poolSize := cfg.PoolSizeV4
	if poolSize == 0 {
		poolSize = DefaultPoolSizeV4
	}
	cidrMask := 32 - int(math.Ceil(math.Log2(float64(poolSize))))

	poolSize6 := cfg.PoolSizeV6
	if poolSize6 == 0 {
		poolSize6 = DefaultPoolSizeV6
	}
	cidrMask6 := 128 - int(math.Ceil(math.Log2(float64(poolSize6))))

	if baseSubnetV4 == "" {
		baseSubnetV4 = "198.18"
	}
	ipStr := baseSubnetV4
	parts := strings.Split(ipStr, ".")
	for len(parts) < 4 {
		ipStr += ".0"
		parts = append(parts, "0")
	}
	var poolStart uint32
	if ip := net.ParseIP(ipStr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			mask := net.CIDRMask(cidrMask, 32)
			ip4 = ip4.Mask(mask)
			poolStart = binary.BigEndian.Uint32(ip4)
		}
	}
	if poolStart == 0 {
		poolStart = 198<<24 | 18<<16
	}

	if baseSubnetV6 == "" {
		baseSubnetV6 = "fd00:18::"
	}
	poolStart6 := net.ParseIP(baseSubnetV6).To16()
	if poolStart6 == nil {
		poolStart6 = make([]byte, 16)
		poolStart6[0] = 0xfd
		poolStart6[1] = 0x00
		poolStart6[3] = 0x18
	}
	mask6 := net.CIDRMask(cidrMask6, 128)
	poolStart6 = poolStart6.Mask(mask6)

	p := &IPPool{
		poolStart:        poolStart,
		poolSize:         poolSize,
		cidrMask:         cidrMask,
		poolStart6:       poolStart6,
		poolSize6:        poolSize6,
		cidrMask6:        cidrMask6,
		stopCh:           make(chan struct{}),
		globalFakeToReal: make(map[IPKey]IPKey),
		globalVersions:   make(map[IPKey]uint64),
	}

	for i := range p.shards {
		p.shards[i] = &cacheShard{
			realToFake: make(map[IPKey]IPKey),
			expiries:   make(map[IPKey]time.Time),
		}
	}

	go p.pruningWorker(10 * time.Minute)

	return p
}

func normalizeIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

func (p *IPPool) getShardIndex(ip net.IP) int {
	ip = normalizeIP(ip)
	return int(fnv1aBytes(ip) % 64)
}

func (p *IPPool) getShard(realIP net.IP) *cacheShard {
	return p.shards[p.getShardIndex(realIP)]
}

func (p *IPPool) AddMapping(realIP, fakeIP net.IP, version uint64, expiresAt time.Time) bool {
	realKey := ToIPKey(realIP)
	fakeKey := ToIPKey(fakeIP)

	p.globalMu.Lock()
	defer p.globalMu.Unlock()

	var oldRealToClear *IPKey
	var oldShardToClear *cacheShard

	if existingReal, exists := p.globalFakeToReal[fakeKey]; exists {
		MetricsCollisions.Add(1)
		if existingVersion, hasVersion := p.globalVersions[fakeKey]; hasVersion {
			if version < existingVersion {
				return false
			}
			if version == existingVersion {
				if bytes.Compare(realKey.ToIP().To16(), existingReal.ToIP().To16()) <= 0 {
					return false
				}
			}
		}
		if existingReal != realKey {
			oldRealToClear = &existingReal
			oldShardToClear = p.getShard(existingReal.ToIP())
		}
	}

	shardReal := p.getShard(realIP)
	shardReal.mu.Lock()
	if existingFake, exists := shardReal.realToFake[realKey]; exists {
		MetricsCollisions.Add(1)
		if existingFake != fakeKey {
			if existingVersion, hasVersion := p.globalVersions[existingFake]; hasVersion {
				if version < existingVersion {
					shardReal.mu.Unlock()
					return false
				}
				if version == existingVersion {
					if bytes.Compare(fakeKey.ToIP().To16(), existingFake.ToIP().To16()) <= 0 {
						shardReal.mu.Unlock()
						return false
					}
				}
			}
			delete(p.globalFakeToReal, existingFake)
			delete(p.globalVersions, existingFake)
		}
	}

	if oldRealToClear != nil {
		if oldShardToClear == shardReal {
			delete(shardReal.realToFake, *oldRealToClear)
			delete(shardReal.expiries, *oldRealToClear)
		} else {
			oldShardToClear.mu.Lock()
			delete(oldShardToClear.realToFake, *oldRealToClear)
			delete(oldShardToClear.expiries, *oldRealToClear)
			oldShardToClear.mu.Unlock()
		}
	}

	shardReal.realToFake[realKey] = fakeKey
	shardReal.expiries[realKey] = expiresAt
	shardReal.mu.Unlock()

	p.globalFakeToReal[fakeKey] = realKey
	p.globalVersions[fakeKey] = version
	return true
}

func (p *IPPool) RemoveMapping(realIP, fakeIP net.IP) {
	realKey := ToIPKey(realIP)
	fakeKey := ToIPKey(fakeIP)

	p.globalMu.Lock()
	defer p.globalMu.Unlock()

	shardReal := p.getShard(realIP)
	shardReal.mu.Lock()
	defer shardReal.mu.Unlock()

	if fKey, ok := shardReal.realToFake[realKey]; ok && fKey == fakeKey {
		delete(shardReal.realToFake, realKey)
		delete(shardReal.expiries, realKey)
		delete(p.globalFakeToReal, fakeKey)
		delete(p.globalVersions, fakeKey)
	}
}

func (p *IPPool) IsFakeIPOccupied(fakeIP net.IP) bool {
	p.globalMu.Lock()
	defer p.globalMu.Unlock()
	_, occupied := p.globalFakeToReal[ToIPKey(fakeIP)]
	return occupied
}

func (p *IPPool) TryReserve(realIP, fakeIP net.IP, version uint64, expiresAt time.Time) (bool, net.IP) {
	realKey := ToIPKey(realIP)
	fakeKey := ToIPKey(fakeIP)

	p.globalMu.Lock()
	defer p.globalMu.Unlock()

	shardReal := p.getShard(realIP)
	shardReal.mu.Lock()
	defer shardReal.mu.Unlock()

	if existingFakeKey, exists := shardReal.realToFake[realKey]; exists {
		if expiry, hasExpiry := shardReal.expiries[realKey]; !hasExpiry || time.Now().Before(expiry) {
			if hasExpiry && time.Now().Add(5*time.Minute).After(expiry) {
				shardReal.expiries[realKey] = expiresAt
			}
			return true, existingFakeKey.ToIP()
		}
		delete(p.globalFakeToReal, existingFakeKey)
		delete(p.globalVersions, existingFakeKey)
		delete(shardReal.realToFake, realKey)
		delete(shardReal.expiries, realKey)
	}

	if _, occupied := p.globalFakeToReal[fakeKey]; occupied {
		return false, nil
	}

	shardReal.realToFake[realKey] = fakeKey
	shardReal.expiries[realKey] = expiresAt
	p.globalFakeToReal[fakeKey] = realKey
	p.globalVersions[fakeKey] = version

	return true, fakeIP
}

func (p *IPPool) PruneExpired() {
	now := time.Now()
	for i := 0; i < 64; i++ {
		shardReal := p.shards[i]
		shardReal.mu.RLock()
		var expired []struct {
			realKey IPKey
			fakeKey IPKey
		}
		for realKey, expiry := range shardReal.expiries {
			if now.After(expiry) {
				if fakeKey, exists := shardReal.realToFake[realKey]; exists {
					expired = append(expired, struct {
						realKey IPKey
						fakeKey IPKey
					}{realKey, fakeKey})
				}
			}
		}
		shardReal.mu.RUnlock()

		if len(expired) > 0 {
			p.globalMu.Lock()
			shardReal.mu.Lock()
			for _, pair := range expired {
				if expiry, exists := shardReal.expiries[pair.realKey]; exists && now.After(expiry) {
					if fKey, ok := shardReal.realToFake[pair.realKey]; ok && fKey == pair.fakeKey {
						delete(shardReal.realToFake, pair.realKey)
						delete(shardReal.expiries, pair.realKey)
						delete(p.globalFakeToReal, pair.fakeKey)
						delete(p.globalVersions, pair.fakeKey)
					}
				}
			}
			shardReal.mu.Unlock()
			p.globalMu.Unlock()
		}
	}
}

func (p *IPPool) GetVersion(fakeIP net.IP) uint64 {
	p.globalMu.Lock()
	defer p.globalMu.Unlock()
	if version, exists := p.globalVersions[ToIPKey(fakeIP)]; exists {
		return version
	}
	return 0
}

func (p *IPPool) GetAllMappings() []Mapping {
	p.globalMu.Lock()
	defer p.globalMu.Unlock()

	mappings := make([]Mapping, 0, len(p.globalFakeToReal))
	for fakeKey, realKey := range p.globalFakeToReal {
		mappings = append(mappings, Mapping{
			FakeIP:  fakeKey.ToIP(),
			RealIP:  realKey.ToIP(),
			Version: p.globalVersions[fakeKey],
		})
	}
	return mappings
}

func (p *IPPool) GetActiveCount() int {
	p.globalMu.Lock()
	defer p.globalMu.Unlock()
	return len(p.globalFakeToReal)
}

func (p *IPPool) Close() {
	close(p.stopCh)
}

func (p *IPPool) pruningWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.PruneExpired()
		}
	}
}

func (p *IPPool) GetPoolSize() uint32 {
	return p.poolSize
}

func (p *IPPool) GetFakeIPsForReals(reals []net.IP, isIPv6 bool) (map[string]net.IP, map[string]MappingInfo, bool) {
	if len(reals) == 0 {
		return nil, nil, false
	}

	sortedReals := make([]net.IP, len(reals))
	copy(sortedReals, reals)
	sort.Slice(sortedReals, func(i, j int) bool {
		return bytes.Compare(sortedReals[i].To16(), sortedReals[j].To16()) < 0
	})

	result := make(map[string]net.IP)
	newMappings := make(map[string]MappingInfo)
	now := time.Now()

	for _, realIP := range sortedReals {
		realKey := ToIPKey(realIP)
		shardReal := p.getShard(realIP)
		shardReal.mu.RLock()
		fakeKey, exists := shardReal.realToFake[realKey]
		expiry := shardReal.expiries[realKey]
		shardReal.mu.RUnlock()

		if exists && now.Add(5*time.Minute).Before(expiry) {
			result[realIP.String()] = fakeKey.ToIP()
			continue
		}

		p.globalMu.Lock()
		shardReal.mu.Lock()

		if existingFakeKey, exists := shardReal.realToFake[realKey]; exists {
			if expiry, hasExpiry := shardReal.expiries[realKey]; !hasExpiry || now.Before(expiry) {
				if hasExpiry && now.Add(5*time.Minute).After(expiry) {
					shardReal.expiries[realKey] = now.Add(MappingTTL)
				}
				result[realIP.String()] = existingFakeKey.ToIP()
				shardReal.mu.Unlock()
				p.globalMu.Unlock()
				continue
			}
			delete(p.globalFakeToReal, existingFakeKey)
			delete(p.globalVersions, existingFakeKey)
			delete(shardReal.realToFake, realKey)
			delete(shardReal.expiries, realKey)
		}

		naturalFake := p.ComputeLevel1Hash(realIP, isIPv6)
		naturalFakeKey := ToIPKey(naturalFake)

		var finalFake net.IP
		if _, occupied := p.globalFakeToReal[naturalFakeKey]; !occupied {
			finalFake = naturalFake
		} else {
			if !isIPv6 {
				naturalVal := binary.BigEndian.Uint32(naturalFake.To4())
				naturalOffset := naturalVal - p.poolStart

				maxAttempts := p.poolSize
				if maxAttempts > 1024 {
					maxAttempts = 1024
				}
				for attempt := uint32(0); attempt < maxAttempts; attempt++ {
					offset := (naturalOffset + attempt) % p.poolSize
					candidateIPVal := p.poolStart + offset
					if candidateIPVal%256 == 0 || candidateIPVal%256 == 255 {
						continue
					}
					candidateIP := net.IPv4(byte(candidateIPVal>>24), byte(candidateIPVal>>16), byte(candidateIPVal>>8), byte(candidateIPVal))
					if _, occupied := p.globalFakeToReal[ToIPKey(candidateIP)]; !occupied {
						finalFake = candidateIP
						break
					}
				}
			} else {
				naturalVal := binary.BigEndian.Uint32(naturalFake[12:16])
				startVal := binary.BigEndian.Uint32(p.poolStart6[12:16])
				naturalOffset := naturalVal - startVal

				maxAttempts := p.poolSize6
				if maxAttempts > 1024 {
					maxAttempts = 1024
				}
				for attempt := uint32(0); attempt < maxAttempts; attempt++ {
					offset := (naturalOffset + attempt) % p.poolSize6
					ip6Bytes := make([]byte, 16)
					copy(ip6Bytes, p.poolStart6)
					binary.BigEndian.PutUint32(ip6Bytes[12:16], startVal+offset)
					candidateIP := net.IP(ip6Bytes)
					if _, occupied := p.globalFakeToReal[ToIPKey(candidateIP)]; !occupied {
						finalFake = candidateIP
						break
					}
				}
			}
		}

		if finalFake != nil {
			allocatedKey := ToIPKey(finalFake)
			shardReal.realToFake[realKey] = allocatedKey
			shardReal.expiries[realKey] = now.Add(MappingTTL)
			p.globalFakeToReal[allocatedKey] = realKey
			p.globalVersions[allocatedKey] = p.GetNextVersion()

			result[realIP.String()] = finalFake
			newMappings[realIP.String()] = MappingInfo{IP: finalFake, Version: p.globalVersions[allocatedKey]}
		} else {
			shardReal.mu.Unlock()
			p.globalMu.Unlock()
			logger.Warn("IPPOOL", "IP pool exhausted when allocating Fake-IP for %v (IPv6=%v)", realIP, isIPv6)
			MetricsExhaustions.Add(1)

			for ipStr, info := range newMappings {
				p.RemoveMapping(net.ParseIP(ipStr), info.IP)
			}

			return nil, nil, false
		}

		shardReal.mu.Unlock()
		p.globalMu.Unlock()

	}

	MetricsAllocations.Add(uint64(len(result)))
	return result, newMappings, true
}

func (p *IPPool) ComputeLevel1Hash(realIP net.IP, isIPv6 bool) net.IP {
	if !isIPv6 {
		offset := fnv1aBytes(realIP.To4()) % p.poolSize
		ipVal := p.poolStart + offset
		if ipVal%256 == 0 {
			ipVal++
		} else if ipVal%256 == 255 {
			ipVal--
		}
		return net.IPv4(byte(ipVal>>24), byte(ipVal>>16), byte(ipVal>>8), byte(ipVal))
	}
	offset := fnv1aBytes(realIP.To16()) % p.poolSize6
	ip6Bytes := make([]byte, 16)
	copy(ip6Bytes, p.poolStart6)
	val := binary.BigEndian.Uint32(ip6Bytes[12:16])
	val += offset
	binary.BigEndian.PutUint32(ip6Bytes[12:16], val)
	return net.IP(ip6Bytes)
}

func (p *IPPool) GetCIDRMask() int {
	return p.cidrMask
}

func (p *IPPool) GetCIDRMask6() int {
	return p.cidrMask6
}

func (p *IPPool) GetPoolNet() string {
	return fmt.Sprintf("%s/%d", UintToIP(p.poolStart), p.cidrMask)
}

func (p *IPPool) GetPoolNet6() string {
	return fmt.Sprintf("%s/%d", net.IP(p.poolStart6).String(), p.cidrMask6)
}

func (p *IPPool) GetNextVersion() uint64 {
	now := uint64(time.Now().UnixNano())
	p.hlcMu.Lock()
	defer p.hlcMu.Unlock()
	if now > p.hlc {
		p.hlc = now
	} else {
		p.hlc++
	}
	return p.hlc
}

func (p *IPPool) ObserveVersion(v uint64) {
	now := uint64(time.Now().UnixNano())
	p.hlcMu.Lock()
	defer p.hlcMu.Unlock()
	if now > p.hlc {
		p.hlc = now
	}
	if v > p.hlc {
		p.hlc = v
	}
}

func UintToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func fnv1aBytes(data []byte) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(data); i++ {
		h ^= uint32(data[i])
		h *= 16777619
	}
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
