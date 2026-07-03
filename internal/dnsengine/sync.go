package dnsengine

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"net"
	"nextpath/internal/logger"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nextpath/internal/netlink"
)

const (
	MsgTypeHandshake = iota
	MsgTypePEX
	MsgTypePing
	MsgTypeMappings
)

type Mapping struct {
	FakeIP  net.IP
	RealIP  net.IP
	Version uint64
}

type SyncMessage struct {
	Type      int
	Handshake *SyncHandshake
	PEXIP     net.IP
	PEXPort   uint16
	Mappings  []Mapping
}

type SafeConn struct {
	net.Conn
	writeChan  chan *SyncMessage
	closed     atomic.Bool
	closeOnce  sync.Once
	peerUUID   uint64
	isOutgoing bool
}

func NewSafeConn(conn net.Conn) *SafeConn {
	sc := &SafeConn{
		Conn:      conn,
		writeChan: make(chan *SyncMessage, 1024),
	}
	go sc.writeLoop()
	return sc
}

func (sc *SafeConn) writeLoop() {
	bw := bufio.NewWriter(sc.Conn)
	enc := gob.NewEncoder(bw)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg := <-sc.writeChan:
			if msg == nil {
				return
			}
			_ = sc.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := enc.Encode(msg)
			if err != nil {
				_ = sc.Close()
				return
			}

			drained := false
			for !drained {
				select {
				case nextMsg := <-sc.writeChan:
					if nextMsg == nil {
						return
					}
					err = enc.Encode(nextMsg)
					if err != nil {
						_ = sc.Close()
						return
					}
				default:
					drained = true
				}
			}

			err = bw.Flush()
			if err != nil {
				_ = sc.Close()
				return
			}
		case <-ticker.C:
			_ = sc.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			err := enc.Encode(&SyncMessage{Type: MsgTypePing})
			if err == nil {
				err = bw.Flush()
			}
			if err != nil {
				_ = sc.Close()
				return
			}
		}
	}
}

func (sc *SafeConn) Close() error {
	var err error
	sc.closeOnce.Do(func() {
		sc.closed.Store(true)
		select {
		case sc.writeChan <- nil:
		default:
		}
		err = sc.Conn.Close()
	})
	return err
}

type SyncHandshake struct {
	UUID           uint64 `json:"uuid"`
	Port           uint16 `json:"port"`
	PoolNet        string `json:"pool_net"`
	PoolNet6       string `json:"pool_net6"`
	SlotsPerDomain uint32 `json:"slots,omitempty"`
	ResultHash     string `json:"hash"`
	AuthToken      string `json:"auth_token"`
}

type SyncManager struct {
	peers            []string
	syncPort         string
	nftClient        *netlink.NFTClient
	mu               sync.RWMutex
	conns            map[string]*SafeConn
	activeDials      map[string]time.Time
	done             chan struct{}
	closeOnce        sync.Once
	dialWg           sync.WaitGroup
	handlersWg       sync.WaitGroup
	nodeUUID         uint64
	poolNet          string
	poolNet6         string
	parsedNetV4      *net.IPNet
	parsedNetV6      *net.IPNet
	resultDir        string
	pool             *IPPool
	authToken        string
	syncPortNum      uint16
	certFingerprints [][]byte
	resultHash       atomic.Pointer[string]

	acceptWg sync.WaitGroup
}

func (s *SyncManager) checkAuthToken(supplied string) bool {
	if s.authToken == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(s.authToken)) == 1
}

func (s *SyncManager) logResultHashDrift(peerAddr, peerHash string) {
	local := s.getResultHash()
	if local == "" || peerHash == "" {
		return
	}
	if local != peerHash {
		logger.Warn("SYNC", "List fingerprint drift with peer %s: local=%s peer=%s", peerAddr, local, peerHash)
	}
}

func readHandshake(dec *gob.Decoder) (*SyncHandshake, error) {
	var msg SyncMessage
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}
	if msg.Type != MsgTypeHandshake || msg.Handshake == nil {
		return nil, fmt.Errorf("expected handshake message")
	}
	return msg.Handshake, nil
}

func getLocalIPs() map[string]bool {
	localIPs := make(map[string]bool)
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				localIP := ipnet.IP
				if ip4 := localIP.To4(); ip4 != nil {
					localIP = ip4
				}
				localIPs[localIP.String()] = true
			}
		}
	}
	return localIPs
}

func NewSyncManager(peersStr string, syncPort string, nftClient *netlink.NFTClient, poolNet string, poolNet6 string, resultDir string, pool *IPPool) *SyncManager {
	var peers []string
	if peersStr != "" {
		for _, p := range strings.Split(peersStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				if !strings.Contains(p, ":") {
					p = p + ":" + syncPort
				}
				peers = append(peers, p)
			}
		}
	}

	portVal, _ := strconv.Atoi(syncPort)
	authToken := os.Getenv("NEXTPATH_SYNC_TOKEN")
	if len(peers) > 0 && authToken == "" {
		logger.Warn("SYNC", "\033[1;33mPEERS is set but NEXTPATH_SYNC_TOKEN is empty\033[0m - peer authentication disabled, relying on nftables allowlist only")
	}

	var customFingerprints [][]byte
	if hashStr := os.Getenv("NEXTPATH_SYNC_CERT_FINGERPRINT"); hashStr != "" {
		for _, part := range strings.Split(hashStr, ",") {
			part = strings.ReplaceAll(strings.TrimSpace(part), ":", "")
			if part == "" {
				continue
			}
			decoded, err := hex.DecodeString(part)
			if err == nil && len(decoded) == 32 {
				customFingerprints = append(customFingerprints, decoded)
			} else {
				logger.Warn("SYNC", "Invalid NEXTPATH_SYNC_CERT_FINGERPRINT format for '%s', expected 32-byte hex", part)
			}
		}
	}

	_, pNet4, _ := net.ParseCIDR(poolNet)
	_, pNet6, _ := net.ParseCIDR(poolNet6)

	s := &SyncManager{
		peers:            peers,
		syncPort:         syncPort,
		nftClient:        nftClient,
		conns:            make(map[string]*SafeConn),
		activeDials:      make(map[string]time.Time),
		done:             make(chan struct{}),
		nodeUUID:         uint64(time.Now().UnixNano()),
		poolNet:          poolNet,
		poolNet6:         poolNet6,
		parsedNetV4:      pNet4,
		parsedNetV6:      pNet6,
		resultDir:        resultDir,
		pool:             pool,
		authToken:        authToken,
		syncPortNum:      uint16(portVal),
		certFingerprints: customFingerprints,
	}
	s.RefreshResultHash()
	return s
}

func (s *SyncManager) RefreshResultHash() {
	domainsHash, _ := os.ReadFile(filepath.Join(s.resultDir, ".hash_domains"))
	ipsHash, _ := os.ReadFile(filepath.Join(s.resultDir, ".hash_ips"))
	combined := strings.TrimSpace(string(domainsHash)) + ":" + strings.TrimSpace(string(ipsHash))
	s.resultHash.Store(&combined)
}

func (s *SyncManager) getResultHash() string {
	if p := s.resultHash.Load(); p != nil {
		return *p
	}
	return ""
}

func (s *SyncManager) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		for _, sc := range s.conns {
			sc.Close()
		}
		s.mu.Unlock()
		s.acceptWg.Wait()
		s.dialWg.Wait()
		s.handlersWg.Wait()
	})
}

func resolvePath(envVal string, defaults []string) string {
	if envVal != "" {
		return envVal
	}
	for _, p := range defaults {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return defaults[len(defaults)-1]
}

func getTLSConfig() (*tls.Config, []byte, error) {
	certFile := resolvePath(os.Getenv("NEXTPATH_SYNC_CERT"), []string{
		"/run/secrets/cert.pem",
		"/app/nextpath/certs/cert.pem",
	})
	keyFile := resolvePath(os.Getenv("NEXTPATH_SYNC_KEY"), []string{
		"/run/secrets/key.pem",
		"/app/nextpath/certs/key.pem",
	})

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("not configured")
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("not configured")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TLS certificates: %v", err)
	}

	var fingerprint []byte
	if len(cert.Certificate) > 0 {
		hash := sha256.Sum256(cert.Certificate[0])
		fingerprint = hash[:]
	}

	logger.Info("SYNC", "Loaded TLS certificate from %s", certFile)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, fingerprint, nil
}

func (s *SyncManager) StartServer() error {
	tlsConfig, fingerprint, err := getTLSConfig()
	if err != nil {
		if err.Error() == "not configured" {
			if len(s.peers) > 0 {
				logger.Error("SYNC", "\033[1;31mConfiguration Error:\033[0m PEERS are defined, but TLS certificates are missing! P2P Sync will NOT start.")
				logger.Error("SYNC", "Please mount TLS certificates (NEXTPATH_SYNC_CERT/KEY), or remove PEERS from your .env")
			}
		} else {
			logger.Error("SYNC", "Failed to initialize TLS for P2P sync: %v", err)
		}
		return nil
	}

	if s.authToken == "" || s.authToken == "change_me_to_a_secure_random_string" {
		logger.Error("SYNC", "\033[1;31mCritical Security Error:\033[0m NEXTPATH_SYNC_TOKEN is empty or set to the default value!")
		logger.Error("SYNC", "P2P Sync will NOT start. You MUST generate a secure random string and set it in your .env")
		return nil
	}
	strictTLSVal := strings.ToLower(strings.TrimSpace(os.Getenv("NEXTPATH_SYNC_STRICT_TLS")))
	isPinning := strictTLSVal == "pinning" || strictTLSVal == "pin"
	skipVerify := strictTLSVal == "false" || strictTLSVal == "0" || strictTLSVal == "n" || strictTLSVal == "no"
	hashStr := strings.TrimSpace(os.Getenv("NEXTPATH_SYNC_CERT_FINGERPRINT"))

	if isPinning {
		if hashStr != "" && len(s.certFingerprints) == 0 {
			logger.Error("SYNC", "\033[1;31mConfiguration Error:\033[0m STRICT_TLS is 'pinning', but NEXTPATH_SYNC_CERT_FINGERPRINT contains invalid hashes.")
			logger.Error("SYNC", "P2P Sync will NOT start. Provide valid 32-byte hex hashes, or leave it empty to auto-pin the local cert.")
			return nil
		}
		if len(s.certFingerprints) == 0 && fingerprint != nil {
			logger.Info("SYNC", "Auto-pinning local TLS certificate for incoming and outgoing P2P verification")
			s.certFingerprints = append(s.certFingerprints, fingerprint)
		}
	} else {
		if hashStr != "" {
			logger.Warn("SYNC", "\033[1;33mConfiguration Warning:\033[0m NEXTPATH_SYNC_CERT_FINGERPRINT is set, but STRICT_TLS is not 'pinning'. Fingerprints will be ignored.")
		}
		if skipVerify {
			logger.Warn("SYNC", "\033[1;33mSecurity Warning:\033[0m NEXTPATH_SYNC_STRICT_TLS is disabled. P2P connections are vulnerable to MITM attacks!")
		}
	}
	listener, err := tls.Listen("tcp", ":"+s.syncPort, tlsConfig)
	if err != nil {
		return err
	}

	logger.Info("SYNC", "TCP Sync Server listening on %s", listener.Addr().String())

	go s.startPeerDiscovery()

	s.acceptWg.Add(1)
	go func() {
		defer s.acceptWg.Done()
		defer listener.Close()
		go func() {
			<-s.done
			listener.Close()
		}()
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.done:
					return
				default:
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
					_ = tcpConn.SetKeepAlive(true)
					_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
				}
			}
			sc := NewSafeConn(conn)
			s.handlersWg.Add(1)
			go s.handleConnection(sc, false)
		}
	}()

	return nil
}

func (s *SyncManager) BroadcastMappings(mappings []Mapping) {
	if len(mappings) == 0 {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.conns) == 0 {
		return
	}

	logger.Debug("SYNC", "Broadcasting %d mappings to %d peers", len(mappings), len(s.conns))

	msg := &SyncMessage{
		Type:     MsgTypeMappings,
		Mappings: mappings,
	}

	for peer, sc := range s.conns {
		if sc.closed.Load() {
			continue
		}
		select {
		case sc.writeChan <- msg:
		default:
			logger.Info("SYNC", "Write queue full for peer %s (slow consumer). Closing connection.", peer)
			_ = sc.Close()
		}
	}
}

func shouldKeepNewConnection(nodeUUID uint64, localSyncPort string, oldConn, newConn *SafeConn, remoteCanonical string) bool {
	if newConn.peerUUID != oldConn.peerUUID {
		return true
	}
	if newConn.isOutgoing == oldConn.isOutgoing {
		return true
	}

	if newConn.isOutgoing {
		if nodeUUID < newConn.peerUUID {
			return true
		} else if nodeUUID == newConn.peerUUID {
			localIP, _, _ := net.SplitHostPort(newConn.Conn.LocalAddr().String())
			localCanonical := net.JoinHostPort(localIP, localSyncPort)
			return localCanonical < remoteCanonical
		}
		return false
	} else {
		if nodeUUID > newConn.peerUUID {
			return true
		} else if nodeUUID == newConn.peerUUID {
			localIP, _, _ := net.SplitHostPort(newConn.Conn.LocalAddr().String())
			localCanonical := net.JoinHostPort(localIP, localSyncPort)
			return localCanonical > remoteCanonical
		}
		return false
	}
}

func (s *SyncManager) handleConnection(sc *SafeConn, isOutgoing bool) {
	defer s.handlersWg.Done()
	defer sc.Close()

	dec := gob.NewDecoder(sc.Conn)

	var selfAddr string
	var peerUUID uint64

	if isOutgoing {
		_ = sc.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		handshake, err := readHandshake(dec)
		if err != nil {
			logger.Error("SYNC", "Failed to read handshake response from %s: %v", sc.Conn.RemoteAddr(), err)
			return
		}
		_ = sc.Conn.SetReadDeadline(time.Time{})

		if !s.checkAuthToken(handshake.AuthToken) {
			logger.Error("SYNC", "Auth token mismatch from %s", sc.Conn.RemoteAddr())
			return
		}
		if handshake.UUID == s.nodeUUID {
			logger.Info("SYNC", "Self-connection detected to %s, dropping", sc.Conn.RemoteAddr())
			return
		}
		peerUUID = handshake.UUID
		tcpAddr, ok := sc.Conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return
		}
		remoteIP := tcpAddr.IP
		if ip4 := remoteIP.To4(); ip4 != nil {
			remoteIP = ip4
		}
		selfAddr = net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(handshake.Port)))
		s.logResultHashDrift(selfAddr, handshake.ResultHash)

		sc.peerUUID = peerUUID
		sc.isOutgoing = true

		s.mu.Lock()
		select {
		case <-s.done:
			s.mu.Unlock()
			return
		default:
		}

		if oldConn, exists := s.conns[selfAddr]; exists && oldConn != sc {
			if shouldKeepNewConnection(s.nodeUUID, s.syncPort, oldConn, sc, selfAddr) {
				logger.Info("SYNC", "Outgoing tie-breaker: keeping outgoing to %s, closing duplicate connection", selfAddr)
				_ = oldConn.Close()
			} else {
				s.mu.Unlock()
				logger.Info("SYNC", "Outgoing tie-breaker: closing outgoing to %s, keeping duplicate connection", selfAddr)
				return
			}
		}
		s.conns[selfAddr] = sc
		delete(s.activeDials, selfAddr)
		s.mu.Unlock()
		logger.Info("SYNC", "Handshake response successful with peer %s", selfAddr)
	} else {
		_ = sc.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		handshake, err := readHandshake(dec)
		if err != nil {
			logger.Error("SYNC", "Failed to read handshake from %s: %v", sc.Conn.RemoteAddr(), err)
			return
		}
		_ = sc.Conn.SetReadDeadline(time.Time{})

		if !s.checkAuthToken(handshake.AuthToken) {
			logger.Error("SYNC", "Auth token mismatch from %s", sc.Conn.RemoteAddr())
			return
		}
		if handshake.UUID == s.nodeUUID {
			logger.Info("SYNC", "Self-connection detected from %s, dropping", sc.Conn.RemoteAddr())
			return
		}
		peerUUID = handshake.UUID
		tcpAddr, ok := sc.Conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return
		}
		remoteIP := tcpAddr.IP
		if ip4 := remoteIP.To4(); ip4 != nil {
			remoteIP = ip4
		}
		selfAddr = net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(handshake.Port)))
		s.logResultHashDrift(selfAddr, handshake.ResultHash)

		if handshake.PoolNet != s.poolNet || handshake.PoolNet6 != s.poolNet6 {
			logger.Error("SYNC", "Configuration mismatch with peer %s! Netv4=%s vs %s, Netv6=%s vs %s",
				selfAddr, s.poolNet, handshake.PoolNet, s.poolNet6, handshake.PoolNet6)
			return
		}

		respHandshake := SyncHandshake{
			UUID:       s.nodeUUID,
			Port:       s.syncPortNum,
			PoolNet:    s.poolNet,
			PoolNet6:   s.poolNet6,
			ResultHash: s.getResultHash(),
			AuthToken:  s.authToken,
		}

		respMsg := &SyncMessage{
			Type:      MsgTypeHandshake,
			Handshake: &respHandshake,
		}
		select {
		case sc.writeChan <- respMsg:
		default:
			return
		}

		sc.peerUUID = peerUUID
		sc.isOutgoing = false

		s.mu.Lock()
		select {
		case <-s.done:
			s.mu.Unlock()
			return
		default:
		}

		if oldConn, exists := s.conns[selfAddr]; exists && oldConn != sc {
			if shouldKeepNewConnection(s.nodeUUID, s.syncPort, oldConn, sc, selfAddr) {
				logger.Info("SYNC", "Incoming tie-breaker: keeping incoming from %s, closing duplicate connection", selfAddr)
				_ = oldConn.Close()
			} else {
				s.mu.Unlock()
				logger.Info("SYNC", "Incoming tie-breaker: closing incoming from %s, keeping duplicate connection", selfAddr)
				return
			}
		}
		s.conns[selfAddr] = sc
		s.mu.Unlock()
		logger.Info("SYNC", "Handshake successful with peer %s", selfAddr)
	}

	if s.pool != nil {
		mappings := s.pool.GetAllMappings()
		s.sendAllMappingsToConn(sc, mappings)
	}

	localIPs := getLocalIPs()

	s.mu.RLock()
	var otherPeers []string
	for addr := range s.conns {
		if addr != selfAddr {
			host, _, err := net.SplitHostPort(addr)
			if err == nil && !localIPs[host] {
				otherPeers = append(otherPeers, addr)
			}
		}
	}
	s.mu.RUnlock()

	for _, otherAddr := range otherPeers {
		s.sendPexMessage(sc, otherAddr)
	}

	s.mu.RLock()
	for addr, otherConn := range s.conns {
		if addr != selfAddr {
			s.sendPexMessage(otherConn, selfAddr)
		}
	}
	s.mu.RUnlock()

	for {
		_ = sc.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		var msg SyncMessage
		err := dec.Decode(&msg)
		if err != nil {
			logger.Info("SYNC", "Connection error from peer %s: %v", selfAddr, err)
			break
		}

		switch msg.Type {
		case MsgTypePEX:
			if msg.PEXPort == 0 || msg.PEXIP.IsLoopback() || msg.PEXIP.IsMulticast() || msg.PEXIP.IsUnspecified() || msg.PEXIP.IsLinkLocalUnicast() {
				logger.Info("SYNC", "Invalid PEX target address %s:%d from peer %s - skipping", msg.PEXIP, msg.PEXPort, selfAddr)
				continue
			}
			s.mu.RLock()
			connCount := len(s.conns)
			s.mu.RUnlock()
			if connCount >= 50 {
				continue
			}
			peerAddr := net.JoinHostPort(msg.PEXIP.String(), strconv.Itoa(int(msg.PEXPort)))
			s.tryConnect(peerAddr, localIPs, "")

		case MsgTypePing:
			continue

		case MsgTypeMappings:
			MetricsSyncs.Add(uint64(len(msg.Mappings)))
			logger.Debug("SYNC", "Received %d mappings from peer %s", len(msg.Mappings), selfAddr)
			for _, m := range msg.Mappings {
				if m.FakeIP == nil || m.RealIP == nil {
					continue
				}
				if !s.isInSubnet(m.FakeIP) {
					logger.Error("SYNC", "Rejected malicious mapping from %s: FakeIP %s is out of bounds", selfAddr, m.FakeIP)
					continue
				}
				if s.pool != nil {
					currentVersion := s.pool.GetVersion(m.FakeIP)
					if currentVersion > m.Version {
						continue
					}
					s.pool.ObserveVersion(m.Version)
					if !s.pool.AddMapping(m.RealIP, m.FakeIP, m.Version, time.Now().Add(MappingTTL)) {
						continue
					}
				}
				if err := s.nftClient.AddMapping(m.FakeIP, m.RealIP, MappingTTL); err != nil {
					logger.Info("SYNC", "Failed to apply synced mapping %s -> %s: %v", m.FakeIP, m.RealIP, err)
				}
			}

		default:
			logger.Error("SYNC", "Protocol violation: unknown command %d from peer %s. Closing connection.", msg.Type, selfAddr)
			goto CLEANUP
		}
	}

CLEANUP:
	if selfAddr != "" {
		s.mu.Lock()
		if s.conns[selfAddr] == sc {
			delete(s.conns, selfAddr)
		}
		s.mu.Unlock()
	}
}

func (s *SyncManager) sendPexMessage(sc *SafeConn, peerAddr string) {
	host, portStr, err := net.SplitHostPort(peerAddr)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}

	msg := &SyncMessage{
		Type:    MsgTypePEX,
		PEXIP:   ip,
		PEXPort: uint16(port),
	}

	if sc.closed.Load() {
		return
	}
	select {
	case sc.writeChan <- msg:
	default:
		logger.Info("SYNC", "Write queue full for peer %s. Closing connection.", peerAddr)
		_ = sc.Close()
	}
}

func (s *SyncManager) sendAllMappingsToConn(sc *SafeConn, mappings []Mapping) {
	var sentCount int
	var currentBatch []Mapping

	for _, m := range mappings {
		currentBatch = append(currentBatch, m)
		sentCount++

		if len(currentBatch) >= 1000 {
			msg := &SyncMessage{
				Type:     MsgTypeMappings,
				Mappings: currentBatch,
			}
			if sc.closed.Load() {
				return
			}
			select {
			case sc.writeChan <- msg:
			default:
				logger.Info("SYNC", "Failed to queue sync mappings for peer. Closing connection.")
				_ = sc.Close()
				return
			}
			currentBatch = nil
			time.Sleep(1 * time.Millisecond)
		}
	}

	if len(currentBatch) > 0 {
		msg := &SyncMessage{
			Type:     MsgTypeMappings,
			Mappings: currentBatch,
		}
		if !sc.closed.Load() {
			select {
			case sc.writeChan <- msg:
			default:
				logger.Info("SYNC", "Write queue full during sync. Closing connection.")
				_ = sc.Close()
				return
			}
		}
	}
	logger.Info("SYNC", "Sent %d mappings to peer %s during cold-start sync", sentCount, sc.Conn.RemoteAddr())
}

func (s *SyncManager) startPeerDiscovery() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	s.discoverAndConnect()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.discoverAndConnect()
		}
	}
}

func (s *SyncManager) discoverAndConnect() {
	localIPs := getLocalIPs()

	for _, peerRaw := range s.peers {
		host, port, err := net.SplitHostPort(peerRaw)
		if err != nil {
			host = peerRaw
			port = s.syncPort
		}

		var ips []net.IP
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			var err error
			ips, err = net.LookupIP(host)
			if err != nil {
				s.tryConnect(net.JoinHostPort(host, port), localIPs, host)
				continue
			}
		}

		for _, ip := range ips {
			ipStr := ip.String()
			if ip4 := ip.To4(); ip4 != nil {
				ipStr = ip4.String()
			}
			if localIPs[ipStr] {
				continue
			}
			peerAddr := net.JoinHostPort(ipStr, port)
			s.tryConnect(peerAddr, localIPs, host)
		}
	}
}

func (s *SyncManager) tryConnect(peerAddr string, localIPs map[string]bool, serverName string) {
	s.mu.Lock()
	if _, exists := s.conns[peerAddr]; exists {
		s.mu.Unlock()
		return
	}
	if dialTime, dialing := s.activeDials[peerAddr]; dialing {
		if time.Since(dialTime) < 10*time.Second {
			s.mu.Unlock()
			return
		}
	}
	s.activeDials[peerAddr] = time.Now()
	s.mu.Unlock()

	host, _, err := net.SplitHostPort(peerAddr)
	if err == nil && localIPs[host] {
		s.mu.Lock()
		delete(s.activeDials, peerAddr)
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	select {
	case <-s.done:
		delete(s.activeDials, peerAddr)
		s.mu.Unlock()
		return
	default:
		s.dialWg.Add(1)
	}
	s.mu.Unlock()
	go func() {
		defer s.dialWg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.activeDials, peerAddr)
			s.mu.Unlock()
		}()

		select {
		case <-s.done:
			return
		default:
		}

		strictTLSVal := strings.ToLower(strings.TrimSpace(os.Getenv("NEXTPATH_SYNC_STRICT_TLS")))
		isPinning := strictTLSVal == "pinning" || strictTLSVal == "pin"
		skipVerify := strictTLSVal == "false" || strictTLSVal == "0" || strictTLSVal == "n" || strictTLSVal == "no"

		tlsConf := &tls.Config{
			InsecureSkipVerify: skipVerify || isPinning,
			ServerName:         serverName,
		}

		if isPinning && len(s.certFingerprints) > 0 {
			tlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("no certificate provided by peer")
				}
				hash := sha256.Sum256(rawCerts[0])
				matched := false
				for _, fp := range s.certFingerprints {
					if bytes.Equal(hash[:], fp) {
						matched = true
						break
					}
				}
				if !matched {
					return fmt.Errorf("certificate fingerprint mismatch (pinning failed)")
				}
				return nil
			}
		}

		dialer := &net.Dialer{Timeout: 3 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", peerAddr, tlsConf)
		if err != nil {
			return
		}

		select {
		case <-s.done:
			conn.Close()
			return
		default:
		}

		if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}

		logger.Info("SYNC", "Connected to peer %s", peerAddr)

		portVal, _ := strconv.Atoi(s.syncPort)
		handshakeObj := SyncHandshake{
			UUID:     s.nodeUUID,
			Port:     uint16(portVal),
			PoolNet:  s.poolNet,
			PoolNet6: s.poolNet6,

			ResultHash: s.getResultHash(),
			AuthToken:  s.authToken,
		}

		sc := NewSafeConn(conn)

		msg := &SyncMessage{
			Type:      MsgTypeHandshake,
			Handshake: &handshakeObj,
		}

		select {
		case sc.writeChan <- msg:
		default:
			logger.Info("SYNC", "Failed to queue handshake for peer %s", peerAddr)
			sc.Close()
			return
		}

		s.handlersWg.Add(1)
		go s.handleConnection(sc, true)
	}()
}

func (s *SyncManager) isInSubnet(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		if s.parsedNetV4 != nil {
			return s.parsedNetV4.Contains(ip)
		}
	} else {
		if s.parsedNetV6 != nil {
			return s.parsedNetV6.Contains(ip)
		}
	}
	return false
}
