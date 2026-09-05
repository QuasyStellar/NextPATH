package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"nextpath/internal/logger"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nextpath/internal/dnsengine"
	"nextpath/internal/netlink"
	"nextpath/internal/parser"
)

func runHealthCheck() {
	proxyAddr := os.Getenv("PROXY_ADDR")
	if proxyAddr == "" {
		proxyAddr = "127.0.0.3"
	}
	proxyPort := os.Getenv("PROXY_PORT")
	if proxyPort == "" {
		proxyPort = "53"
	}
	target := net.JoinHostPort(proxyAddr, proxyPort)

	conn, err := net.DialTimeout("udp", target, 5*time.Second)
	if err != nil {
		fmt.Printf("Healthcheck failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte{
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00,
		0x00, 0x02,
		0x00, 0x01,
	}

	if _, err := conn.Write(msg); err != nil {
		fmt.Printf("Healthcheck failed to write: %v\n", err)
		os.Exit(1)
	}

	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil {
		fmt.Printf("Healthcheck failed to read: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Healthcheck OK")
	os.Exit(0)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		runHealthCheck()
	}

	debugMode := getEnvBool("DEBUG", false)
	logger.Init(debugMode)

	resultDir := getEnv("RESULT_DIR", "/app/nextpath/result")
	listSource := getEnv("LIST_SOURCE", "")
	remoteSource := listSource
	compileLocal := getEnvBool("COMPILE_LOCAL", listSource == "")

	pollIntervalStr := getEnv("LIST_POLL_INTERVAL", "2h")
	maxTTLStr := getEnv("MAX_FAKE_IP_TTL", "300")
	syncPort := getEnv("SYNC_PORT", "5353")
	peers := getEnv("PEERS", "")

	pollInterval, err := time.ParseDuration(pollIntervalStr)
	if err != nil {
		logger.Info("ENGINE", "Invalid LIST_POLL_INTERVAL '%s', falling back to 2h", pollIntervalStr)
		pollInterval = 2 * time.Hour
	}

	maxTTL, err := strconv.ParseUint(maxTTLStr, 10, 32)
	if err != nil {
		logger.Info("ENGINE", "Invalid MAX_FAKE_IP_TTL '%s', falling back to 300", maxTTLStr)
		maxTTL = 300
	}

	runUpdaterOnly := getEnvBool("RUN_UPDATER", false)
	for _, arg := range os.Args {
		if arg == "--updater" {
			runUpdaterOnly = true
		}
	}

	if runUpdaterOnly {
		logger.Info("UPDATER", "Starting in standalone updater mode...")
		if getEnvBool("COMPILE_ONLY", false) {
			logger.Info("UPDATER", "Running single compilation/bootstrap (COMPILE_ONLY)...")
			cfg := getCompileConfig(resultDir)
			if compileLocal {
				err := parser.CompileLists(cfg)
				if err != nil {
					logger.Error("UPDATER", "COMPILE_ONLY failed: %v", err)
					os.Exit(1)
				}
			} else {
				if remoteSource != "" && (strings.HasPrefix(remoteSource, "http://") || strings.HasPrefix(remoteSource, "https://")) {
					b, _ := os.ReadFile(filepath.Join(resultDir, ".etag"))
					meta := strings.TrimSpace(string(b))
					var lastETag, lastLastMod string
					if parts := strings.SplitN(meta, "\n", 2); len(parts) == 2 {
						lastETag = strings.TrimSpace(parts[0])
						lastLastMod = strings.TrimSpace(parts[1])
					} else {
						lastETag = meta
					}
					newETag, newLastMod, err := downloadRemoteFiles(remoteSource, resultDir, lastETag, lastLastMod)
					if err != nil {
						logger.Error("UPDATER", "COMPILE_ONLY failed: %v", err)
						os.Exit(1)
					}
					_ = os.WriteFile(filepath.Join(resultDir, ".etag"), []byte(newETag+"\n"+newLastMod), 0644)
				}
			}
			logger.Info("UPDATER", "Compilation/bootstrap finished. Exiting.")
			os.Exit(0)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		go func() {
			startUpdaterLoop(ctx, remoteSource, resultDir, pollInterval, compileLocal)
		}()

		sig := <-sigChan
		logger.Info("UPDATER", "Received signal %v, shutting down updater...", sig)
		return
	}

	logger.Info("ENGINE", "\033[1;32mNextPATH\033[0m Engine starting...")

	domainsHashFile := filepath.Join(resultDir, ".hash_domains")
	proxyRPZFile := filepath.Join(resultDir, "proxy.rpz")
	for {
		if _, err1 := os.Stat(domainsHashFile); err1 == nil {
			if _, err2 := os.Stat(proxyRPZFile); err2 == nil {
				break
			}
		}
		logger.Info("ENGINE", "Waiting for compiled lists to be prepared by the updater...")
		time.Sleep(2 * time.Second)
	}

	fakeNetV4 := getEnv("FAKE_IP", "198.18")
	fakeNetV6 := getEnv("FAKE_IP6", "fd00:18::")

	poolCfg := getIPPoolConfig()
	pool := dnsengine.NewIPPoolWithConfig(nil, fakeNetV4, fakeNetV6, poolCfg)
	defer pool.Close()
	poolNet := pool.GetPoolNet()
	poolNet6 := pool.GetPoolNet6()
	logger.Info("ENGINE", "Allocated Fake-IP subnets: IPv4=%s, IPv6=%s", poolNet, poolNet6)

	if err = netlink.InitStructure(poolNet, poolNet6); err != nil {
		logger.Error("ENGINE", "\033[1;31mCritical:\033[0m Failed to initialize nftables structure: %v", err)
		os.Exit(1)
	}
	logger.Info("ENGINE", "nftables base ruleset checked/initialized successfully")

	nftClient, err := netlink.NewNFTClient()
	if err != nil {
		logger.Error("ENGINE", "\033[1;31mCritical:\033[0m Failed to connect to Netlink nftables: %v", err)
		os.Exit(1)
	}
	defer nftClient.Close()

	if err := nftClient.ReloadDenySets(resultDir); err != nil {
		logger.Info("ENGINE", "\033[1;33mWarning:\033[0m failed to load deny IP sets: %v", err)
	}

	if existingMappings, err := nftClient.ReadExistingMappings(); err == nil {
		for fakeStr, record := range existingMappings {
			if fakeIP := net.ParseIP(fakeStr); fakeIP != nil {
				pool.AddMapping(record.RealIP, fakeIP, 0, time.Now().Add(record.Expires))
			}
		}
		logger.Info("ENGINE", "Recovered %d active mappings from nftables into memory", len(existingMappings))
	} else {
		logger.Info("ENGINE", "Failed to read existing mappings from nftables: %v", err)
	}

	syncMgr := dnsengine.NewSyncManager(peers, syncPort, nftClient, poolNet, poolNet6, resultDir, pool)
	err = syncMgr.StartServer()
	if err != nil {
		logger.Error("ENGINE", "\033[1;31mCritical:\033[0m Failed to start TCP Sync Server: %v", err)
		os.Exit(1)
	}

	proxyAddr := getEnv("PROXY_ADDR", "127.0.0.3")
	proxyPort := getEnv("PROXY_PORT", "53")
	dnsAddr2 := getEnv("DNS_ADDR_2", "127.0.0.2")
	metricsEnable := getEnv("METRICS_ENABLE", "false")
	metricsAddr := getEnv("METRICS_ADDR", "127.0.0.1")
	metricsPort := getEnv("METRICS_PORT", "9090")

	if strings.ToLower(metricsEnable) == "true" || metricsEnable == "1" || metricsEnable == "y" {
		if net.ParseIP(metricsAddr) == nil {
			logger.Error("MAIN", "\033[1;31mConfiguration Error:\033[0m Invalid METRICS_ADDR: %s. Using 127.0.0.1", metricsAddr)
			metricsAddr = "127.0.0.1"
		}
		if p, err := strconv.Atoi(metricsPort); err != nil || p < 1 || p > 65535 {
			logger.Error("MAIN", "\033[1;31mConfiguration Error:\033[0m Invalid METRICS_PORT: %s. Using 9090", metricsPort)
			metricsPort = "9090"
		}
		dnsengine.StartMetricsServer(metricsAddr, metricsPort, pool)
	}

	enableIPv6 := getEnvBool("ENABLE_IPV6", true)

	dnsProxy := dnsengine.NewDNSProxy(
		net.JoinHostPort(proxyAddr, proxyPort),
		net.JoinHostPort(dnsAddr2, "53"),
		pool,
		nftClient,
		syncMgr,
		uint32(maxTTL),
		enableIPv6,
	)

	errChan := make(chan error, 1)
	go func() {
		if err := dnsProxy.Start(); err != nil {
			logger.Error("ENGINE", "DNS Proxy \033[1;31mfailed\033[0m: %v", err)
			errChan <- err
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		startFileWatcher(ctx, resultDir, nftClient, syncMgr)
	}()

	logger.Info("ENGINE", "\033[1;32mNextPATH\033[0m is fully initialized and ready to process traffic!")

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		select {
		case sig := <-shutdownChan:
			logger.Info("ENGINE", "Received signal %v, shutting down...", sig)
			goto SHUTDOWN
		case err := <-errChan:
			logger.Error("ENGINE", "Fatal \033[1;31merror\033[0m, shutting down: %v", err)
			goto SHUTDOWN
		}
	}

SHUTDOWN:
	time.AfterFunc(10*time.Second, func() {
		logger.Error("ENGINE", "Shutdown timed out after 10s, forcing exit")
		os.Exit(1)
	})
	cancel()
	syncMgr.Close()
	_ = dnsProxy.Close()
	logger.Info("ENGINE", "\033[1;32mNextPATH\033[0m Engine stopped gracefully")
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		val := strings.TrimSpace(value)
		val = strings.Trim(val, `"'`)
		if val != "" {
			return val
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	val := strings.ToLower(strings.TrimSpace(getEnv(key, "")))
	if val == "" {
		return defaultVal
	}
	return val == "true" || val == "1" || val == "y" || val == "yes"
}

func getCompileConfig(resultDir string) parser.CompileConfig {
	aggLimitStr := getEnv("AGGREGATE_COUNT", "500")
	aggLimit, err := strconv.Atoi(aggLimitStr)
	if err != nil {
		aggLimit = 500
	}
	return parser.CompileConfig{
		SourcesDir:   getEnv("SOURCES_DIR", "/app/nextpath/lists/sources"),
		ManualDir:    getEnv("MANUAL_DIR", "/app/nextpath/lists/manual"),
		ResultDir:    resultDir,
		DownloadDir:  getEnv("DOWNLOAD_DIR", "/app/nextpath/download"),
		RouteAll:     getEnvBool("ROUTE_ALL", false),
		FilterCasino: getEnvBool("FILTER_CASINO", true),
		BlockAds:     getEnvBool("BLOCK_ADS", true),
		EnableIPv6:   getEnvBool("ENABLE_IPV6", true),
		Limit:        aggLimit,
	}
}

func startUpdaterLoop(ctx context.Context, source string, resultDir string, interval time.Duration, compileLocal bool) {
	if compileLocal {
		compileIntervalStr := getEnv("COMPILE_INTERVAL", "24h")
		if ci, err := time.ParseDuration(compileIntervalStr); err == nil {
			interval = ci
		} else {
			interval = 24 * time.Hour
		}
	}

	now := time.Now().UTC()
	nextTick := now.Truncate(interval).Add(interval)
	initialDelay := nextTick.Sub(now)

	if compileLocal {
		logger.Info("UPDATER", "Next compilation scheduled at %s UTC (in %v), interval: %v", nextTick.Format("15:04:05"), initialDelay.Round(time.Second), interval)
	} else {
		logger.Info("UPDATER", "Next update check scheduled at %s UTC (in %v), interval: %v", nextTick.Format("15:04:05"), initialDelay.Round(time.Second), interval)
	}

	runReload := func() {
		if compileLocal {
			logger.Info("UPDATER", "Re-compiling local lists...")
			cfg := getCompileConfig(resultDir)
			err := parser.CompileLists(cfg)
			if err == nil {
				logger.Info("UPDATER", "\033[1;32mSuccessfully\033[0m re-compiled local list")
			} else {
				logger.Error("UPDATER", "Compilation \033[1;31mfailed\033[0m: %v", err)
			}
			return
		}

		if !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://") {
			return
		}

		b, _ := os.ReadFile(filepath.Join(resultDir, ".etag"))
		meta := strings.TrimSpace(string(b))
		var lastETag, lastLastMod string
		if parts := strings.SplitN(meta, "\n", 2); len(parts) == 2 {
			lastETag = strings.TrimSpace(parts[0])
			lastLastMod = strings.TrimSpace(parts[1])
		} else {
			lastETag = meta
		}

		newETag, newLastMod, err := downloadRemoteFiles(source, resultDir, lastETag, lastLastMod)
		if err != nil {
			logger.Error("UPDATER", "\033[1;31mFailed\033[0m to update remote lists: %v", err)
			return
		}

		if newETag != lastETag || newLastMod != lastLastMod {
			_ = os.WriteFile(filepath.Join(resultDir, ".etag"), []byte(newETag+"\n"+newLastMod), 0644)
			logger.Info("UPDATER", "\033[1;32mSuccessfully\033[0m updated remote lists")
		}
	}

	runReload()

	timer := time.NewTimer(initialDelay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		runReload()
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runReload()
		}
	}
}

func startFileWatcher(ctx context.Context, resultDir string, nftClient *netlink.NFTClient, syncMgr *dnsengine.SyncManager) {
	domainsHashFile := filepath.Join(resultDir, ".hash_domains")
	ipsHashFile := filepath.Join(resultDir, ".hash_ips")

	getLastMod := func() (time.Time, time.Time) {
		t1, _ := os.Stat(domainsHashFile)
		t2, _ := os.Stat(ipsHashFile)
		var m1, m2 time.Time
		if t1 != nil {
			m1 = t1.ModTime()
		}
		if t2 != nil {
			m2 = t2.ModTime()
		}
		return m1, m2
	}

	lastM1, lastM2 := getLastMod()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	logger.Info("WATCHER", "Watching result directory for list updates...")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m1, m2 := getLastMod()
			if !m1.Equal(lastM1) || !m2.Equal(lastM2) {
				lastM1, lastM2 = m1, m2
				logger.Info("WATCHER", "Detected changes in compiled list files. Reloading configurations...")

				parser.ClearKnotCache()

				if err := nftClient.ReloadDenySets(resultDir); err != nil {
					logger.Error("WATCHER", "Failed to reload deny IP sets: %v", err)
				}

				if syncMgr != nil {
					syncMgr.RefreshResultHash()
				}
			}
		}
	}
}

func downloadRemoteFiles(sourceURL, targetDir, lastETag, lastModified string) (string, string, error) {
	archiveURL := sourceURL
	if !strings.HasSuffix(archiveURL, ".tar.gz") {
		if strings.HasSuffix(archiveURL, "/") {
			archiveURL = archiveURL + "result.tar.gz"
		} else {
			archiveURL = archiveURL + "/result.tar.gz"
		}
	}

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", archiveURL, nil)
	if err != nil {
		return "", "", err
	}
	if lastETag != "" {
		req.Header.Set("If-None-Match", lastETag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch archive %s: %w", archiveURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return lastETag, lastModified, nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("failed to download archive from %s: status code %d", archiveURL, resp.StatusCode)
	}

	newETag := resp.Header.Get("ETag")
	newLastMod := resp.Header.Get("Last-Modified")
	if newETag == "" && newLastMod == "" {
		newETag = "no-cache-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to initialize gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	_ = os.MkdirAll(targetDir, 0755)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", fmt.Errorf("failed to read tar header: %w", err)
		}

		cleanedPath := filepath.Clean(header.Name)
		targetPath := filepath.Join(targetDir, cleanedPath)
		if !strings.HasPrefix(targetPath, filepath.Clean(targetDir)+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(targetPath, 0755)
		case tar.TypeReg:
			err = func() error {
				_ = os.MkdirAll(filepath.Dir(targetPath), 0755)
				tmpPath := targetPath + ".tmp"
				outFile, openErr := os.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode)&0755)
				if openErr != nil {
					return fmt.Errorf("failed to create temp file %s: %w", tmpPath, openErr)
				}

				cleanup := func() { _ = os.Remove(tmpPath) }

				if header.Size > 500*1024*1024 {
					_ = outFile.Close()
					cleanup()
					return fmt.Errorf("file %s is too large (%d bytes)", header.Name, header.Size)
				}
				if _, copyErr := io.Copy(outFile, tarReader); copyErr != nil {
					_ = outFile.Close()
					cleanup()
					return copyErr
				}
				if syncErr := outFile.Sync(); syncErr != nil {
					_ = outFile.Close()
					cleanup()
					return syncErr
				}
				if closeErr := outFile.Close(); closeErr != nil {
					cleanup()
					return closeErr
				}
				if renameErr := os.Rename(tmpPath, targetPath); renameErr != nil {
					cleanup()
					return renameErr
				}
				return nil
			}()
			if err != nil {
				return "", "", err
			}
		}
	}

	return newETag, newLastMod, nil
}

func getIPPoolConfig() dnsengine.IPPoolConfig {
	var cfg dnsengine.IPPoolConfig

	poolV4Str := getEnv("POOL_SIZE_V4", getEnv("POOL_SIZE", ""))
	if poolV4Str != "" {
		poolV4Str = strings.TrimPrefix(poolV4Str, "/")
		if val, err := strconv.ParseUint(poolV4Str, 10, 32); err == nil {
			if val > 0 && val <= 32 {
				cfg.PoolSizeV4 = 1 << (32 - val)
			} else {
				logger.Warn("ENGINE", "Invalid CIDR mask for POOL_SIZE_V4. Falling back to /8")
				cfg.PoolSizeV4 = 1 << 24
			}
		}
	}

	poolV6Str := getEnv("POOL_SIZE_V6", "")
	if poolV6Str != "" {
		poolV6Str = strings.TrimPrefix(poolV6Str, "/")
		if val, err := strconv.ParseUint(poolV6Str, 10, 32); err == nil {
			if val > 0 && val <= 128 {
				if (128 - val) > 31 {
					cfg.PoolSizeV6 = 1 << 31
				} else {
					cfg.PoolSizeV6 = 1 << (128 - val)
				}
			} else {
				logger.Warn("ENGINE", "Invalid CIDR mask for POOL_SIZE_V6. Falling back to /104")
				cfg.PoolSizeV6 = 1 << 24
			}
		}
	}

	return cfg
}
