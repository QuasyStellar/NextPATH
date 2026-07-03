package dnsengine

import (
	"net"
	"nextpath/internal/logger"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"nextpath/internal/netlink"
)

type DNSProxy struct {
	pool      atomic.Pointer[IPPool]
	nftClient *netlink.NFTClient
	syncMgr   *SyncManager
	upstreams []string
	maxTTL    uint32
	server    *dns.Server
	serverTCP *dns.Server
	udpClient *dns.Client
	tcpClient *dns.Client
}

func NewDNSProxy(listenAddr, upstreamAddr string, pool *IPPool, nftClient *netlink.NFTClient, syncMgr *SyncManager, maxTTL uint32) *DNSProxy {
	proxy := &DNSProxy{
		nftClient: nftClient,
		syncMgr:   syncMgr,
		upstreams: []string{upstreamAddr},
		maxTTL:    maxTTL,
		udpClient: &dns.Client{Timeout: 2 * time.Second},
		tcpClient: &dns.Client{Net: "tcp", Timeout: 2 * time.Second},
	}
	proxy.pool.Store(pool)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", proxy.handleDNSRequest)

	proxy.server = &dns.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: mux,
		UDPSize: dns.MaxMsgSize,
	}

	proxy.serverTCP = &dns.Server{
		Addr:         listenAddr,
		Net:          "tcp",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	return proxy
}

func (p *DNSProxy) UpdatePool(newPool *IPPool) {
	oldPool := p.pool.Swap(newPool)
	if oldPool != nil {
		oldPool.Close()
	}
}

func (p *DNSProxy) GetPool() *IPPool {
	return p.pool.Load()
}

func (p *DNSProxy) Start() error {
	logger.Info("PROXY", "DNS Proxy listening on %s (UDP/TCP)", p.server.Addr)

	errChan := make(chan error, 2)
	go func() { errChan <- p.server.ListenAndServe() }()
	go func() { errChan <- p.serverTCP.ListenAndServe() }()

	err := <-errChan
	_ = p.Close()
	return err
}

func (p *DNSProxy) Close() error {
	_ = p.serverTCP.Shutdown()
	return p.server.Shutdown()
}

func (p *DNSProxy) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	MetricsDNSQueries.Add(1)
	if len(r.Question) == 0 {
		msg := new(dns.Msg)
		msg.SetReply(r)
		_ = w.WriteMsg(msg)
		return
	}

	pool := p.GetPool()

	resp, err := p.resolveUpstream(r)
	if err != nil {
		MetricsDNSErrors.Add(1)
		dns.HandleFailed(w, r)
		return
	}

	var realV4 []net.IP
	var realV6 []net.IP
	addV4 := func(ip net.IP) {
		ip4 := ip.To4()
		if ip4 == nil {
			return
		}
		if ip4.Equal(net.IPv4zero) {
			return
		}
		for _, existing := range realV4 {
			if existing.Equal(ip4) {
				return
			}
		}
		realV4 = append(realV4, ip4)
	}

	addV6 := func(ip net.IP) {
		if ip.To4() != nil {
			return
		}
		if ip.Equal(net.IPv6zero) || ip.Equal(net.IPv6unspecified) {
			return
		}
		for _, existing := range realV6 {
			if existing.Equal(ip) {
				return
			}
		}
		realV6 = append(realV6, ip)
	}

	extractSVCBHints := func(values []dns.SVCBKeyValue) {
		for _, kv := range values {
			if kv.Key() == dns.SVCB_IPV4HINT {
				if hint, ok := kv.(*dns.SVCBIPv4Hint); ok {
					for _, ip := range hint.Hint {
						addV4(ip)
					}
				}
			} else if kv.Key() == dns.SVCB_IPV6HINT {
				if hint, ok := kv.(*dns.SVCBIPv6Hint); ok {
					for _, ip := range hint.Hint {
						addV6(ip)
					}
				}
			}
		}
	}

	collectIPs := func(rr dns.RR) {
		switch record := rr.(type) {
		case *dns.A:
			addV4(record.A)
		case *dns.AAAA:
			addV6(record.AAAA)
		case *dns.SVCB:
			extractSVCBHints(record.Value)
		case *dns.HTTPS:
			extractSVCBHints(record.Value)
		}
	}

	for _, rr := range resp.Answer {
		collectIPs(rr)
	}
	for _, rr := range resp.Ns {
		collectIPs(rr)
	}
	for _, rr := range resp.Extra {
		collectIPs(rr)
	}

	var mapV4 map[string]net.IP
	var newV4 map[string]MappingInfo
	var mapV6 map[string]net.IP
	var newV6 map[string]MappingInfo
	var ok bool

	if len(realV4) > 0 {
		mapV4, newV4, ok = pool.GetFakeIPsForReals(realV4, false)
		if !ok {
			dns.HandleFailed(w, r)
			return
		}
	} else {
		mapV4 = make(map[string]net.IP)
	}

	if len(realV6) > 0 {
		mapV6, newV6, ok = pool.GetFakeIPsForReals(realV6, true)
		if !ok {
			for realStr, info := range newV4 {
				pool.RemoveMapping(net.ParseIP(realStr), info.IP)
			}
			dns.HandleFailed(w, r)
			return
		}
	} else {
		mapV6 = make(map[string]net.IP)
	}

	go func() {
		var toBroadcast []Mapping

		for realStr, info := range newV4 {
			fake := info.IP
			parsedIP := net.ParseIP(realStr)
			if parsedIP == nil {
				continue
			}
			realIP := parsedIP.To4()
			if p.nftClient != nil {
				err := p.nftClient.AddMapping(fake, realIP, MappingTTL)
				if err != nil {
					logger.Info("PROXY", "Failed to write mapping %s -> %s: %v", fake, realIP, err)
				} else {
					logger.Debug("PROXY", "Applied mapping %s -> %s", fake, realIP)
				}
			}
			if p.syncMgr != nil {
				toBroadcast = append(toBroadcast, Mapping{FakeIP: fake, RealIP: realIP, Version: info.Version})
			}
		}

		for realStr, info := range newV6 {
			fake := info.IP
			parsedIP := net.ParseIP(realStr)
			if parsedIP == nil {
				continue
			}
			realIP := parsedIP.To16()
			if p.nftClient != nil {
				err := p.nftClient.AddMapping(fake, realIP, MappingTTL)
				if err != nil {
					logger.Info("PROXY", "Failed to write mapping %s -> %s: %v", fake, realIP, err)
				} else {
					logger.Debug("PROXY", "Applied mapping %s -> %s", fake, realIP)
				}
			}
			if p.syncMgr != nil {
				toBroadcast = append(toBroadcast, Mapping{FakeIP: fake, RealIP: realIP, Version: info.Version})
			}
		}

		if p.syncMgr != nil && len(toBroadcast) > 0 {
			p.syncMgr.BroadcastMappings(toBroadcast)
		}
	}()

	filterRRs := func(rrs []dns.RR) []dns.RR {
		n := 0
		for _, rr := range rrs {
			switch record := rr.(type) {
			case *dns.A:
				if fake, exists := mapV4[record.A.String()]; exists {
					record.A = fake
					record.Header().Ttl = min(record.Header().Ttl, p.maxTTL)
					rrs[n] = record
					n++
				} else {
					rrs[n] = record
					n++
				}
			case *dns.AAAA:
				if fake, exists := mapV6[record.AAAA.String()]; exists {
					record.AAAA = fake
					record.Header().Ttl = min(record.Header().Ttl, p.maxTTL)
					rrs[n] = record
					n++
				} else {
					rrs[n] = record
					n++
				}
			case *dns.SVCB:
				record.Value = patchSVCBValues(record.Value, mapV4, mapV6)
				record.Header().Ttl = min(record.Header().Ttl, p.maxTTL)
				rrs[n] = record
				n++
			case *dns.HTTPS:
				record.Value = patchSVCBValues(record.Value, mapV4, mapV6)
				record.Header().Ttl = min(record.Header().Ttl, p.maxTTL)
				rrs[n] = record
				n++
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3:
				continue
			default:
				rrs[n] = rr
				n++
			}
		}
		return rrs[:n]
	}

	resp.Answer = filterRRs(resp.Answer)
	resp.Ns = filterRRs(resp.Ns)
	resp.Extra = filterRRs(resp.Extra)
	resp.MsgHdr.AuthenticatedData = false

	_ = w.WriteMsg(resp)
}

func (p *DNSProxy) resolveUpstream(r *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, upstream := range p.upstreams {
		resp, _, err := p.udpClient.Exchange(r, upstream)
		if err == nil {
			if resp.Truncated {
				respTCP, _, errTCP := p.tcpClient.Exchange(r, upstream)
				if errTCP == nil {
					return respTCP, nil
				}
			}
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func patchSVCBValues(values []dns.SVCBKeyValue, mapV4 map[string]net.IP, mapV6 map[string]net.IP) []dns.SVCBKeyValue {
	var newValues []dns.SVCBKeyValue
	for _, kv := range values {
		switch kv.Key() {
		case dns.SVCB_IPV4HINT:
			if hint, ok := kv.(*dns.SVCBIPv4Hint); ok {
				var newHints []net.IP
				for _, ip := range hint.Hint {
					if fake, exists := mapV4[ip.String()]; exists {
						newHints = append(newHints, fake)
					}
				}
				hint.Hint = newHints
			}
			newValues = append(newValues, kv)
		case dns.SVCB_IPV6HINT:
			if hint, ok := kv.(*dns.SVCBIPv6Hint); ok {
				var newHints []net.IP
				for _, ip := range hint.Hint {
					if fake, exists := mapV6[ip.String()]; exists {
						newHints = append(newHints, fake)
					}
				}
				hint.Hint = newHints
			}
			newValues = append(newValues, kv)
		default:
			newValues = append(newValues, kv)
		}
	}
	return newValues
}
