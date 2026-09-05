package netlink

import (
	"fmt"
	"net"
	"nextpath/internal/logger"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
)

const (
	tableName = "nextpath"

	batchMaxSize  = 256
	batchChanSize = 8192
)

func parseBoolEnv(key string, defaultVal bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return defaultVal
	}
	return v == "true" || v == "1" || v == "y" || v == "yes"
}

type mappingOp struct {
	fakeIP  net.IP
	realIP  net.IP
	timeout time.Duration
	done    chan error
}

type NFTClient struct {
	conn       *nftables.Conn
	muConn     sync.Mutex
	batchCh    chan mappingOp
	cancelCh   chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
	enableIPv6 bool
}

func NewNFTClient() (*NFTClient, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nftables Netlink: %w", err)
	}
	c := &NFTClient{
		conn:       conn,
		batchCh:    make(chan mappingOp, batchChanSize),
		cancelCh:   make(chan struct{}),
		done:       make(chan struct{}),
		enableIPv6: parseBoolEnv("ENABLE_IPV6", true),
	}

	go c.batchWorker()
	return c, nil
}

func (c *NFTClient) Close() {
	c.closeOnce.Do(func() {
		close(c.cancelCh)
		<-c.done
		c.muConn.Lock()
		if c.conn != nil {
			_ = c.conn.CloseLasting()
			c.conn = nil
		}
		c.muConn.Unlock()
	})
}

func (c *NFTClient) Reconnect() error {
	c.muConn.Lock()
	defer c.muConn.Unlock()
	return c.reconnectLocked()
}

func (c *NFTClient) reconnectLocked() error {
	if c.conn != nil {
		_ = c.conn.CloseLasting()
		c.conn = nil
	}
	for i := 0; i < 5; i++ {
		newConn, err := nftables.New()
		if err == nil {
			c.conn = newConn
			logger.Info("NFTABLES", "Netlink socket reconnected successfully")
			return nil
		}
		logger.Info("NFTABLES", "Reconnect attempt %d/5 failed: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}
	err := fmt.Errorf("failed to reconnect Netlink socket after 5 attempts")
	logger.Error("NFTABLES", "CRITICAL: %v", err)
	return err
}

func (c *NFTClient) batchWorker() {
	defer close(c.done)

	batch := make([]mappingOp, 0, batchMaxSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		c.muConn.Lock()
		err := c.flushBatchLocked(batch)
		c.muConn.Unlock()

		var finalErr error
		if err != nil {
			if strings.Contains(err.Error(), "file exists") {
				logger.Debug("NFTABLES", "Batch flush contained duplicates (file exists) - ignored due to stateless hashing")
			} else {
				logger.Info("NFTABLES", "Batch flush failed (%d ops): %v — reconnecting", len(batch), err)
				c.muConn.Lock()
				if retryErr := c.reconnectLocked(); retryErr == nil {
					if retryErr2 := c.flushBatchLocked(batch); retryErr2 != nil && !strings.Contains(retryErr2.Error(), "file exists") {
						logger.Info("NFTABLES", "Batch retry also failed (%d ops): %v", len(batch), retryErr2)
						finalErr = retryErr2
					}
				} else {
					finalErr = err
				}
				c.muConn.Unlock()
			}
		}

		for _, op := range batch {
			if op.done != nil {
				if finalErr != nil {
					op.done <- finalErr
				}
				close(op.done)
			}
		}

		batch = batch[:0]
	}

	for {
		select {
		case <-c.cancelCh:
			flush()
			return
		case op := <-c.batchCh:
			batch = append(batch, op)

			draining := true
			for draining && len(batch) < batchMaxSize {
				select {
				case <-c.cancelCh:
					flush()
					return
				case nextOp := <-c.batchCh:
					batch = append(batch, nextOp)
				default:
					draining = false
				}
			}

			flush()

		}
	}
}

func (c *NFTClient) flushBatchLocked(batch []mappingOp) error {
	if c.conn == nil {
		return fmt.Errorf("netlink connection is not established")
	}
	tb := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}

	v4Map := &nftables.Set{
		Table:      tb,
		Name:       "v4_map",
		IsMap:      true,
		HasTimeout: true,
	}
	v6Map := &nftables.Set{
		Table:      tb,
		Name:       "v6_map",
		IsMap:      true,
		HasTimeout: true,
	}

	v4ToAdd := make([]nftables.SetElement, 0, len(batch))
	v6ToAdd := make([]nftables.SetElement, 0, len(batch))

	for _, op := range batch {
		isIPv6 := op.fakeIP.To4() == nil
		if isIPv6 && !c.enableIPv6 {
			continue
		}

		var keyBytes, valBytes []byte
		if isIPv6 {
			keyBytes = op.fakeIP.To16()
			valBytes = op.realIP.To16()
		} else {
			keyBytes = op.fakeIP.To4()
			valBytes = op.realIP.To4()
		}

		if keyBytes == nil || valBytes == nil {
			continue
		}

		el := nftables.SetElement{
			Key:     keyBytes,
			Val:     valBytes,
			Timeout: op.timeout,
		}

		if isIPv6 {
			v6ToAdd = append(v6ToAdd, el)
		} else {
			v4ToAdd = append(v4ToAdd, el)
		}
	}

	if len(v4ToAdd) > 0 {
		if err := c.conn.SetAddElements(v4Map, v4ToAdd); err != nil {
			return fmt.Errorf("failed to add %d v4 elements: %w", len(v4ToAdd), err)
		}
	}
	if c.enableIPv6 && len(v6ToAdd) > 0 {
		if err := c.conn.SetAddElements(v6Map, v6ToAdd); err != nil {
			return fmt.Errorf("failed to add %d v6 elements: %w", len(v6ToAdd), err)
		}
	}

	if len(v4ToAdd) > 0 || len(v6ToAdd) > 0 {
		if err := c.conn.Flush(); err != nil {
			return fmt.Errorf("batch add flush failed: %w", err)
		}
	}

	logger.Debug("NFTABLES", "Flushed %d new firewall rules (%d IPv4, %d IPv6)", len(batch), len(v4ToAdd), len(v6ToAdd))

	return nil
}

func getDenyElements(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var ips []string
	for _, line := range strings.Split(string(content), "\n") {
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "/") {
			if _, _, err := net.ParseCIDR(line); err != nil {
				logger.Info("NFTABLES", "Skipping invalid CIDR in deny list: %s", line)
				continue
			}
		} else if net.ParseIP(line) == nil {
			logger.Info("NFTABLES", "Skipping invalid IP in deny list: %s", line)
			continue
		}
		ips = append(ips, line)
	}
	if len(ips) == 0 {
		return ""
	}
	return strings.Join(ips, ", ")
}

func (c *NFTClient) ReloadDenySets(listsDir string) error {
	denyElements := getDenyElements(filepath.Join(listsDir, "deny-ips-v4.txt"))
	denyElementsV6 := getDenyElements(filepath.Join(listsDir, "deny-ips-v6.txt"))
	enableIPv6 := parseBoolEnv("ENABLE_IPV6", true)

	var configBuilder strings.Builder
	configBuilder.WriteString(fmt.Sprintf("flush set inet %s deny_v4\n", tableName))
	if denyElements != "" {
		configBuilder.WriteString(fmt.Sprintf("add element inet %s deny_v4 { %s }\n", tableName, denyElements))
	}

	if enableIPv6 {
		configBuilder.WriteString(fmt.Sprintf("flush set inet %s deny_v6\n", tableName))
		if denyElementsV6 != "" {
			configBuilder.WriteString(fmt.Sprintf("add element inet %s deny_v6 { %s }\n", tableName, denyElementsV6))
		}
	}

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(configBuilder.String())

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload deny sets: %v, output: %s", err, string(out))
	}

	logger.Info("NFTABLES", "Deny IP sets reloaded successfully")
	return nil
}

type MappingRecovery struct {
	RealIP  net.IP
	Expires time.Duration
}

func (c *NFTClient) ReadExistingMappings() (map[string]MappingRecovery, error) {
	c.muConn.Lock()
	defer c.muConn.Unlock()

	if c.conn == nil {
		return nil, fmt.Errorf("netlink connection is not established")
	}

	mappings := make(map[string]MappingRecovery)
	tb := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}

	v4Map := &nftables.Set{
		Table: tb,
		Name:  "v4_map",
		IsMap: true,
	}
	elements, err := c.conn.GetSetElements(v4Map)
	if err != nil && !strings.Contains(err.Error(), "no such file or directory") {
		return nil, fmt.Errorf("failed to get v4 elements: %w", err)
	} else if err == nil {
		for _, el := range elements {
			fake := net.IP(el.Key)
			real := net.IP(el.Val)
			mappings[fake.String()] = MappingRecovery{
				RealIP:  real,
				Expires: el.Expires,
			}
		}
	}

	enableIPv6 := parseBoolEnv("ENABLE_IPV6", true)
	if enableIPv6 {
		v6Map := &nftables.Set{
			Table: tb,
			Name:  "v6_map",
			IsMap: true,
		}
		elements6, err := c.conn.GetSetElements(v6Map)
		if err != nil && !strings.Contains(err.Error(), "no such file or directory") {
			return nil, fmt.Errorf("failed to get v6 elements: %w", err)
		} else if err == nil {
			for _, el := range elements6 {
				fake := net.IP(el.Key)
				real := net.IP(el.Val)
				mappings[fake.String()] = MappingRecovery{
					RealIP:  real,
					Expires: el.Expires,
				}
			}
		}
	}

	return mappings, nil
}

func InitStructure(poolNet, poolNet6 string) error {

	dohEnable := parseBoolEnv("DOH_ENABLE", false)
	dohPort := os.Getenv("DOH_PORT")
	if _, err := strconv.Atoi(dohPort); err != nil || dohPort == "" {
		dohPort = "443"
	}
	publicDNS := parseBoolEnv("PUBLIC_DNS", false)
	dnsRateLimit := os.Getenv("DNS_RATE_LIMIT")
	if _, err := strconv.Atoi(dnsRateLimit); err != nil || dnsRateLimit == "" {
		dnsRateLimit = "300"
	}
	enableIPv6 := parseBoolEnv("ENABLE_IPV6", true)
	allowedV4 := "{ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }"
	allowedV6 := "{ ::1/128, fe80::/10, fd00::/8 }"

	var configStr string
	configStr += fmt.Sprintf("table inet %s {\n", tableName)
	configStr += "    map v4_map { type ipv4_addr : ipv4_addr; flags dynamic, timeout; timeout 2h; }\n"
	if enableIPv6 {
		configStr += "    map v6_map { type ipv6_addr : ipv6_addr; flags dynamic, timeout; timeout 2h; }\n"
	}
	configStr += "    set deny_v4 { type ipv4_addr; flags interval; }\n"
	configStr += "    set dns_udp_meter { type ipv4_addr; flags dynamic; size 65535; }\n"
	configStr += "    set dns_tcp_new_meter { type ipv4_addr; flags dynamic; size 65535; }\n"
	configStr += "    set dns_tcp_meter { type ipv4_addr; flags dynamic; size 65535; }\n"
	configStr += "    set doh_tcp_new_meter { type ipv4_addr; flags dynamic; size 65535; }\n"
	configStr += "    set doh_tcp_meter { type ipv4_addr; flags dynamic; size 65535; }\n"
	if enableIPv6 {
		configStr += "    set deny_v6 { type ipv6_addr; flags interval; }\n"
		configStr += "    set dns_udp6_meter { type ipv6_addr; flags dynamic; size 65535; }\n"
		configStr += "    set dns_tcp6_new_meter { type ipv6_addr; flags dynamic; size 65535; }\n"
		configStr += "    set dns_tcp6_meter { type ipv6_addr; flags dynamic; size 65535; }\n"
		configStr += "    set doh_tcp6_new_meter { type ipv6_addr; flags dynamic; size 65535; }\n"
		configStr += "    set doh_tcp6_meter { type ipv6_addr; flags dynamic; size 65535; }\n"
	}

	configStr += "    chain input {\n"
	configStr += "        type filter hook input priority 0; policy accept;\n"
	configStr += "        iifname \"lo\" accept\n"
	configStr += "        ct state established,related accept\n"
	configStr += "        ip saddr @deny_v4 drop\n"
	if enableIPv6 {
		configStr += "        ip6 saddr @deny_v6 drop\n"
	}
	if !publicDNS {
		configStr += fmt.Sprintf("        ip saddr != %s udp dport 53 drop\n", allowedV4)
		configStr += fmt.Sprintf("        ip saddr != %s tcp dport 53 drop\n", allowedV4)
		if dohEnable && dohPort != "443" {
			configStr += fmt.Sprintf("        ip saddr != %s tcp dport %s drop\n", allowedV4, dohPort)
		}
		if enableIPv6 {
			configStr += fmt.Sprintf("        ip6 saddr != %s udp dport 53 drop\n", allowedV6)
			configStr += fmt.Sprintf("        ip6 saddr != %s tcp dport 53 drop\n", allowedV6)
			if dohEnable && dohPort != "443" {
				configStr += fmt.Sprintf("        ip6 saddr != %s tcp dport %s drop\n", allowedV6, dohPort)
			}
		}
	}

	syncPort := os.Getenv("SYNC_PORT")
	if _, err := strconv.Atoi(syncPort); err != nil || syncPort == "" {
		syncPort = "5353"
	}

	peersStr := os.Getenv("PEERS")
	var peerV4 []string
	var peerV6 []string
	if peersStr != "" {
		for _, p := range strings.Split(peersStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				host, _, err := net.SplitHostPort(p)
				if err != nil {
					host = p
				}
				if ip := net.ParseIP(host); ip != nil {
					if ip.To4() != nil {
						peerV4 = append(peerV4, ip.String())
					} else {
						peerV6 = append(peerV6, ip.String())
					}
				} else {
					ips, err := net.LookupIP(host)
					if err == nil {
						for _, resolvedIP := range ips {
							if resolvedIP.To4() != nil {
								peerV4 = append(peerV4, resolvedIP.String())
							} else {
								peerV6 = append(peerV6, resolvedIP.String())
							}
						}
					}
				}
			}
		}
	}

	for _, pip := range peerV4 {
		configStr += fmt.Sprintf("        ip saddr %s tcp dport %s accept\n", pip, syncPort)
	}
	if enableIPv6 {
		for _, pip := range peerV6 {
			configStr += fmt.Sprintf("        ip6 saddr %s tcp dport %s accept\n", pip, syncPort)
		}
	}

	configStr += fmt.Sprintf("        ip saddr != %s tcp dport %s drop\n", allowedV4, syncPort)
	if enableIPv6 {
		configStr += fmt.Sprintf("        ip6 saddr != %s tcp dport %s drop\n", allowedV6, syncPort)
	}

	configStr += fmt.Sprintf("        udp dport 53 add @dns_udp_meter { ip saddr limit rate %s/second } accept\n", dnsRateLimit)
	configStr += fmt.Sprintf("        tcp dport 53 ct state new add @dns_tcp_new_meter { ip saddr limit rate %s/second } accept\n", dnsRateLimit)
	configStr += fmt.Sprintf("        tcp dport 53 add @dns_tcp_meter { ip saddr limit rate %s/second } accept\n", dnsRateLimit)
	if enableIPv6 {
		configStr += fmt.Sprintf("        udp dport 53 add @dns_udp6_meter { ip6 saddr limit rate %s/second } accept\n", dnsRateLimit)
		configStr += fmt.Sprintf("        tcp dport 53 ct state new add @dns_tcp6_new_meter { ip6 saddr limit rate %s/second } accept\n", dnsRateLimit)
		configStr += fmt.Sprintf("        tcp dport 53 add @dns_tcp6_meter { ip6 saddr limit rate %s/second } accept\n", dnsRateLimit)
	}
	if dohEnable && dohPort != "443" {
		configStr += fmt.Sprintf("        tcp dport %s ct state new add @doh_tcp_new_meter { ip saddr limit rate %s/second } accept\n", dohPort, dnsRateLimit)
		configStr += fmt.Sprintf("        tcp dport %s add @doh_tcp_meter { ip saddr limit rate %s/second } accept\n", dohPort, dnsRateLimit)
		if enableIPv6 {
			configStr += fmt.Sprintf("        tcp dport %s ct state new add @doh_tcp6_new_meter { ip6 saddr limit rate %s/second } accept\n", dohPort, dnsRateLimit)
			configStr += fmt.Sprintf("        tcp dport %s add @doh_tcp6_meter { ip6 saddr limit rate %s/second } accept\n", dohPort, dnsRateLimit)
		}
	}
	configStr += "        udp dport 53 drop\n"
	configStr += "        tcp dport 53 drop\n"
	if dohEnable && !publicDNS && dohPort != "443" {
		configStr += fmt.Sprintf("        tcp dport %s drop\n", dohPort)
	}
	configStr += "    }\n"

	configStr += "    chain forward {\n"
	configStr += "        type filter hook forward priority 0; policy accept;\n"
	configStr += "        ip saddr @deny_v4 drop\n"
	configStr += fmt.Sprintf("        ct original ip daddr %s ct status dnat update @v4_map { ct original ip daddr : ip daddr }\n", poolNet)
	if enableIPv6 {
		configStr += "        ip6 saddr @deny_v6 drop\n"
		configStr += fmt.Sprintf("        ct original ip6 daddr %s ct status dnat update @v6_map { ct original ip6 daddr : ip6 daddr }\n", poolNet6)
	}
	configStr += "    }\n"

	configStr += "    chain output {\n"
	configStr += "        type filter hook output priority 0; policy accept;\n"
	configStr += fmt.Sprintf("        ct original ip daddr %s ct status dnat update @v4_map { ct original ip daddr : ip daddr }\n", poolNet)
	if enableIPv6 {
		configStr += fmt.Sprintf("        ct original ip6 daddr %s ct status dnat update @v6_map { ct original ip6 daddr : ip6 daddr }\n", poolNet6)
	}
	configStr += "    }\n"

	configStr += "    chain postrouting {\n"
	configStr += "        type nat hook postrouting priority 100; policy accept;\n"
	configStr += "        masquerade\n"
	configStr += "    }\n"

	configStr += "    chain filter_postrouting {\n"
	configStr += "        type filter hook postrouting priority 300; policy accept;\n"
	configStr += "        tcp flags syn tcp option maxseg size set rt mtu\n"
	configStr += "    }\n"

	configStr += "    chain raw_prerouting {\n"
	configStr += "        type filter hook prerouting priority -300; policy accept;\n"
	configStr += "        iifname \"lo\" notrack\n"
	configStr += "    }\n"

	configStr += "    chain raw_output {\n"
	configStr += "        type filter hook output priority -300; policy accept;\n"
	configStr += "        oifname \"lo\" notrack\n"
	configStr += "    }\n"

	configStr += "    chain nat_prerouting {\n"
	configStr += "        type nat hook prerouting priority -100; policy accept;\n"
	configStr += fmt.Sprintf("        ip daddr %s dnat ip to ip daddr map @v4_map\n", poolNet)
	if enableIPv6 {
		configStr += fmt.Sprintf("        ip6 daddr %s dnat ip6 to ip6 daddr map @v6_map\n", poolNet6)
	}
	configStr += "    }\n"

	configStr += "    chain nat_output {\n"
	configStr += "        type nat hook output priority -100; policy accept;\n"
	configStr += fmt.Sprintf("        ip daddr %s dnat ip to ip daddr map @v4_map\n", poolNet)
	if enableIPv6 {
		configStr += fmt.Sprintf("        ip6 daddr %s dnat ip6 to ip6 daddr map @v6_map\n", poolNet6)
	}
	configStr += "    }\n"
	configStr += "}\n"

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(configStr)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w: %s", err, output)
	}

	return nil
}

func (c *NFTClient) AddMapping(fakeIP, realIP net.IP, timeout time.Duration) error {
	if fakeIP == nil || realIP == nil {
		return fmt.Errorf("invalid address: fake=%v, real=%v", fakeIP, realIP)
	}
	if !c.enableIPv6 && fakeIP.To4() == nil {
		return nil
	}

	fakeIPCopy := make(net.IP, len(fakeIP))
	copy(fakeIPCopy, fakeIP)
	realIPCopy := make(net.IP, len(realIP))
	copy(realIPCopy, realIP)

	done := make(chan error, 1)
	op := mappingOp{fakeIP: fakeIPCopy, realIP: realIPCopy, timeout: timeout, done: done}

	select {
	case c.batchCh <- op:
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			return fmt.Errorf("timeout waiting for mapping application")
		}
	default:
		logger.Warn("NFTABLES", "Batch channel full, dropping mapping for %v", fakeIPCopy)
		return fmt.Errorf("batch queue is full")
	}
}
