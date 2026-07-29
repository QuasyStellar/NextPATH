package parser

import (
	"bufio"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"

	"encoding/hex"
	"fmt"
	"io"

	"net"
	"net/http"
	"nextpath/internal/logger"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go4.org/netipx"
	"golang.org/x/net/idna"
	"golang.org/x/sync/errgroup"
	"net/netip"
)

type CompileConfig struct {
	SourcesDir   string
	ManualDir    string
	ResultDir    string
	DownloadDir  string
	RouteAll     bool
	FilterCasino bool
	BlockAds     bool
	EnableIPv6   bool
	Limit        int
}

type DomainRule struct {
	Domain string
	IsEx   bool
}

func buildSimpleRPZ(rules []DomainRule) ([]string, []string) {
	inc := make(map[string]struct{})
	excMap := make(map[string]struct{})
	for _, r := range rules {
		if r.IsEx {
			excMap[r.Domain] = struct{}{}
		} else {
			inc[r.Domain] = struct{}{}
		}
	}
	union := make([]string, 0, len(inc)+len(excMap))
	for d := range inc {
		union = append(union, d)
	}
	for d := range excMap {
		union = append(union, d)
	}
	unionOpt := CollapseDomains(union)

	var final []string
	for _, d := range unionOpt {
		if _, isExc := excMap[d]; !isExc {
			final = append(final, d)
		}
	}

	excRaw := make([]string, 0, len(excMap))
	for d := range excMap {
		excRaw = append(excRaw, d)
	}
	exc := CollapseDomains(excRaw)
	return final, exc
}

func CompileLists(cfg CompileConfig) error {
	logger.Debug("COMPILER", "Starting local compilation of zones...")
	startTime := time.Now()

	if cfg.Limit <= 0 {
		cfg.Limit = 500
	}

	if err := os.MkdirAll(cfg.ResultDir, 0755); err != nil {
		return err
	}
	downloadDir := cfg.DownloadDir
	if downloadDir == "" {
		downloadDir = "/app/nextpath/download"
	}
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return err
	}

	logger.Debug("COMPILER", "Checking remote sources for updates...")
	downloadSources(cfg)

	currentIPsHash := getStateHash(cfg, "ips")
	currentDomainsHash := getStateHash(cfg, "domains")
	hashIPsFile := filepath.Join(cfg.ResultDir, ".hash_ips")
	hashDomainsFile := filepath.Join(cfg.ResultDir, ".hash_domains")

	cachedIPsBytes, _ := os.ReadFile(hashIPsFile)
	cachedIPsHash := strings.TrimSpace(string(cachedIPsBytes))

	cachedDomainsBytes, _ := os.ReadFile(hashDomainsFile)
	cachedDomainsHash := strings.TrimSpace(string(cachedDomainsBytes))

	compileIPsNeeded := (cachedIPsHash == "" || cachedIPsHash != currentIPsHash || !fileExists(filepath.Join(cfg.ResultDir, "route-ips-v4.txt")) || !fileExists(filepath.Join(cfg.ResultDir, "route-ips-v6.txt")))
	compileDomainsNeeded := (cachedDomainsHash == "" || cachedDomainsHash != currentDomainsHash || !fileExists(filepath.Join(cfg.ResultDir, "proxy.rpz")) || !fileExists(filepath.Join(cfg.ResultDir, "adblock.rpz")) || !fileExists(filepath.Join(cfg.ResultDir, "deny.rpz")) || !fileExists(filepath.Join(cfg.ResultDir, "deny2.rpz")))

	if !compileIPsNeeded && !compileDomainsNeeded {
		logger.Info("COMPILER", "No changes detected in local configurations or remote sources. Skipping compilation.")
		return nil
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-time.After(15 * time.Second):
			logger.Info("COMPILER", "Still working... Please wait, processing millions of rules can take up to 2 minutes.")
		case <-done:
			return
		}
	}()
	defer close(done)

	var incIps, excIps, denyIps []netip.Prefix
	var pDoms, pExc, adFinal, adExcl, mFinal, mExc, d2Final, d2Exc []string
	var casP map[string]struct{}
	var adIntEx map[string]struct{}
	var hpr, har, hae, hmr, hd2r, exPOnly, exG []DomainRule
	var rawP, rawAd, rawManual, rawD2 map[string]struct{}

	var proxyIncluded, proxyExcluded, proxyFiltered int
	var adRaw, adExcluded, adIntExCount, adFiltered int

	var ipStats IPCompileResult
	if compileIPsNeeded {
		logger.Debug("COMPILER", "Loading IP lists concurrently...")
		var eg errgroup.Group
		eg.Go(func() error { incIps, _ = loadIPs(cfg, "include-ips"); return nil })
		eg.Go(func() error { excIps, _ = loadIPs(cfg, "exclude-ips"); return nil })
		eg.Go(func() error { denyIps, _ = loadIPs(cfg, "deny-ips"); return nil })
		_ = eg.Wait()

		logger.Debug("COMPILER", "Processing and subtracting IP ranges...")
		ipStats = compileIPs(cfg, incIps, excIps, denyIps)
	}

	if compileDomainsNeeded {
		logger.Debug("COMPILER", "Loading domain lists concurrently...")
		var eg errgroup.Group
		eg.Go(func() error {
			hpr, casP, rawP = loadDomainsWithRules(cfg, "include-hosts", cfg.FilterCasino)
			return nil
		})
		eg.Go(func() error {
			if cfg.BlockAds {
				har, _, rawAd = loadDomainsWithRules(cfg, "include-adblock-hosts", false)
			}
			return nil
		})
		eg.Go(func() error {
			if cfg.BlockAds {
				hae, _, _ = loadDomainsWithRules(cfg, "exclude-adblock-hosts", false)
			}
			return nil
		})
		eg.Go(func() error { hmr, _, rawManual = loadDomainsWithRules(cfg, "rpz", false); return nil })
		eg.Go(func() error { hd2r, _, rawD2 = loadDomainsWithRules(cfg, "rpz2", false); return nil })
		eg.Go(func() error { exPOnly, _, _ = loadDomainsWithRules(cfg, "exclude-hosts", false); return nil })
		eg.Go(func() error { exG, _, _ = loadDomainsWithRules(cfg, "remove-hosts", false); return nil })
		_ = eg.Wait()

		exCommon := make(map[string]struct{})
		for _, r := range exG {
			exCommon[r.Domain] = struct{}{}
		}

		logger.Debug("COMPILER", "Compiling proxy.rpz...")
		pInc := make(map[string]struct{})
		pExcRaw := make(map[string]struct{})

		for _, r := range exG {
			pExcRaw[r.Domain] = struct{}{}
		}
		for _, r := range exPOnly {
			pExcRaw[r.Domain] = struct{}{}
		}
		for _, r := range hpr {
			if r.IsEx {
				pExcRaw[r.Domain] = struct{}{}
			} else {
				pInc[r.Domain] = struct{}{}
			}
		}

		piS := stripPrefixesMap(pInc)
		peS := pExcRaw

		union := make([]string, 0, len(piS)+len(peS))
		for d := range piS {
			union = append(union, d)
		}
		for d := range peS {
			union = append(union, d)
		}
		unionOptimized := CollapseDomains(union)

		pDoms = make([]string, 0)
		for _, d := range unionOptimized {
			if _, isExc := peS[d]; !isExc {
				pDoms = append(pDoms, d)
			}
		}
		peSSlice := make([]string, 0, len(peS))
		for d := range peS {
			peSSlice = append(peSSlice, d)
		}
		pExc = CollapseDomains(peSSlice)

		proxyIncluded = len(pInc)
		proxyExcluded = len(pExcRaw)
		proxyFiltered = len(casP)

		logger.Debug("COMPILER", "Compiling adblock.rpz...")
		adInc := make(map[string]struct{})
		adExcExt := make(map[string]struct{})
		adIntEx = make(map[string]struct{})

		extLookup := make(map[string]struct{})
		for _, r := range hae {
			extLookup[r.Domain] = struct{}{}
		}

		for _, r := range append(har, hae...) {
			if r.IsEx {
				if _, ok := extLookup[r.Domain]; ok {
					adExcExt[r.Domain] = struct{}{}
				} else {
					adIntEx[r.Domain] = struct{}{}
				}
			} else {
				adInc[r.Domain] = struct{}{}
			}
		}
		adAllExc := make(map[string]struct{})
		for d := range adExcExt {
			adAllExc[d] = struct{}{}
		}
		for d := range adIntEx {
			adAllExc[d] = struct{}{}
		}
		for d := range exCommon {
			adAllExc[d] = struct{}{}
		}

		adUnion := make([]string, 0, len(adInc)+len(adAllExc))
		for d := range adInc {
			adUnion = append(adUnion, d)
		}
		for d := range adAllExc {
			adUnion = append(adUnion, d)
		}

		adUnionOptimized := CollapseDomains(adUnion)

		adFinal = make([]string, 0)
		for _, d := range adUnionOptimized {
			if _, isExc := adAllExc[d]; !isExc {
				adFinal = append(adFinal, d)
			}
		}

		adExclRaw := make([]string, 0, len(adExcExt)+len(adIntEx))
		for d := range adExcExt {
			adExclRaw = append(adExclRaw, d)
		}
		for d := range adIntEx {
			adExclRaw = append(adExclRaw, d)
		}
		adExcl = CollapseDomains(adExclRaw)

		adRaw = len(har)
		adExcluded = len(adExcExt)
		adIntExCount = len(adIntEx)
		adFiltered = adRaw - len(adFinal) - adExcluded - adIntExCount
		if adFiltered < 0 {
			adFiltered = 0
		}

		logger.Debug("COMPILER", "Compiling deny.rpz...")
		mFinal, mExc = buildSimpleRPZ(hmr)

		logger.Debug("COMPILER", "Compiling deny2.rpz...")
		d2Final, d2Exc = buildSimpleRPZ(hd2r)

		writeRPZFile(filepath.Join(cfg.ResultDir, "proxy.rpz"), pDoms, pExc, uniqueSliceFromMap(rawP), cfg.RouteAll)
		writeRPZFile(filepath.Join(cfg.ResultDir, "adblock.rpz"), adFinal, adExcl, uniqueSliceFromMap(rawAd), false)
		writeRPZFile(filepath.Join(cfg.ResultDir, "deny.rpz"), mFinal, mExc, uniqueSliceFromMap(rawManual), false)
		writeRPZFile(filepath.Join(cfg.ResultDir, "deny2.rpz"), d2Final, d2Exc, uniqueSliceFromMap(rawD2), false)

	} else {
		logger.Debug("COMPILER", "Skipping domain lists compilation (no changes detected).")
	}

	if compileIPsNeeded {
		_ = os.WriteFile(hashIPsFile, []byte(currentIPsHash), 0644)
	}
	if compileDomainsNeeded {
		_ = os.WriteFile(hashDomainsFile, []byte(currentDomainsHash), 0644)
	}

	if compileIPsNeeded || compileDomainsNeeded {
		logger.Info("COMPILER", "Compilation tasks finished in %v!", time.Since(startTime))
	} else {
		logger.Info("COMPILER", "Compilation tasks finished (no changes detected)")
	}

	if compileIPsNeeded {
		logger.Info("ENGINE", "=============================================")
		logger.Info("ENGINE", " IPv4 Routes:")
		logger.Info("ENGINE", "   Included:     %d", ipStats.V4RawRoutes)
		logger.Info("ENGINE", "   Excluded:     %d", ipStats.V4ExcRoutes)
		logger.Info("ENGINE", "   Result:       %d", ipStats.V4AggrRoutes)
		logger.Info("ENGINE", "---------------------------------------------")
		logger.Info("ENGINE", " IPv6 Routes:")
		logger.Info("ENGINE", "   Included:     %d", ipStats.V6RawRoutes)
		logger.Info("ENGINE", "   Excluded:     %d", ipStats.V6ExcRoutes)
		logger.Info("ENGINE", "   Result:       %d", ipStats.V6AggrRoutes)
		logger.Info("ENGINE", "---------------------------------------------")
		logger.Info("ENGINE", " IPv4 Deny:")
		logger.Info("ENGINE", "   Included:     %d", ipStats.V4RawDeny)
		logger.Info("ENGINE", "   Result:       %d", ipStats.V4AggrDeny)
		logger.Info("ENGINE", "---------------------------------------------")
		logger.Info("ENGINE", " IPv6 Deny:")
		logger.Info("ENGINE", "   Included:     %d", ipStats.V6RawDeny)
		logger.Info("ENGINE", "   Result:       %d", ipStats.V6AggrDeny)
		logger.Info("ENGINE", "=============================================")
	}

	if compileDomainsNeeded {
		logger.Info("ENGINE", "=============================================")
		logger.Info("ENGINE", " Proxy:")
		logger.Info("ENGINE", "   Included:     %d", proxyIncluded)
		logger.Info("ENGINE", "   Filtered:     %d", proxyFiltered)
		logger.Info("ENGINE", "   Excluded:     %d", proxyExcluded)
		logger.Info("ENGINE", "   Result:       %d", len(pDoms))
		logger.Info("ENGINE", "---------------------------------------------")
		logger.Info("ENGINE", " AdBlock:")
		logger.Info("ENGINE", "   Included:     %d", adRaw)
		logger.Info("ENGINE", "   Filtered:     %d", adFiltered)
		logger.Info("ENGINE", "   Excluded:     %d", adExcluded)
		logger.Info("ENGINE", "   Internal Ex:  %d", adIntExCount)
		logger.Info("ENGINE", "   Result:       %d", len(adFinal))
		logger.Info("ENGINE", "---------------------------------------------")
		logger.Info("ENGINE", " Global Remove:  %d", len(exG))
		logger.Info("ENGINE", "=============================================")
	}

	ClearKnotCache()

	return nil
}

func ClearKnotCache() {
	files, err := os.ReadDir("/run/knot-resolver/control")
	if err != nil {
		return
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "1") || strings.HasPrefix(f.Name(), "2") {
			sockPath := "/run/knot-resolver/control/" + f.Name()
			if conn, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond); err == nil {
				_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
				_, _ = conn.Write([]byte("cache.clear()\n"))
				buf := make([]byte, 128)
				_, _ = conn.Read(buf)
				_ = conn.Close()
			}
		}
	}
}

func loadDomainsWithRules(cfg CompileConfig, name string, filterCasino bool) ([]DomainRule, map[string]struct{}, map[string]struct{}) {
	var urls []string
	sourcesFile := filepath.Join(cfg.SourcesDir, name+".txt")
	if strings.Contains(name, "rpz") && !strings.Contains(name, "rpz2") {
		sourcesFile = filepath.Join(cfg.SourcesDir, "rpz.txt")
	} else if strings.Contains(name, "rpz2") {
		sourcesFile = filepath.Join(cfg.SourcesDir, "rpz2.txt")
	}

	urls, _ = readUrls(sourcesFile)

	isExF := strings.HasPrefix(name, "exclude") || strings.HasPrefix(name, "remove")
	isRpzF := strings.Contains(name, "rpz")
	isAdF := strings.Contains(name, "adblock")
	isDomF := (strings.Contains(name, "hosts") || strings.Contains(name, "domain")) && !isAdF

	downloadedRules, casRules, rawRules := downloadAllWithRules(cfg, name, urls, isExF, isRpzF, isDomF, filterCasino)

	manualFile := filepath.Join(cfg.ManualDir, name+".txt")
	manRules, manCas, manRaw := validateFile(manualFile, filterCasino, isExF, isRpzF, isDomF)

	downloadedRules = append(downloadedRules, manRules...)
	for d := range manCas {
		casRules[d] = struct{}{}
	}
	for r := range manRaw {
		rawRules[r] = struct{}{}
	}

	return downloadedRules, casRules, rawRules
}

func downloadAllWithRules(cfg CompileConfig, stem string, urls []string, isExF, isRpzF, isDomF, filterCasino bool) ([]DomainRule, map[string]struct{}, map[string]struct{}) {
	var mu sync.Mutex
	rules := make([]DomainRule, 0)
	casSet := make(map[string]struct{})
	rawRules := make(map[string]struct{})

	if len(urls) == 0 {
		return rules, casSet, rawRules
	}

	downloadDir := cfg.DownloadDir
	if downloadDir == "" {
		downloadDir = "/app/nextpath/download"
	}

	var eg errgroup.Group
	eg.SetLimit(10)
	for _, u := range urls {
		u := u
		eg.Go(func() error {
			cachedFile := getCachedFilepath(downloadDir, u, stem)
			if _, err := os.Stat(cachedFile); err != nil {
				if err := downloadOrGetCached(downloadDir, u, stem); err != nil {
					logger.Warn("COMPILER", "\033[1;33mWarning:\033[0m failed to download %s: %v", u, err)
				}
			}
			o, c, r := validateFile(cachedFile, filterCasino, isExF, isRpzF, isDomF)
			mu.Lock()
			rules = append(rules, o...)
			for d := range c {
				casSet[d] = struct{}{}
			}
			for line := range r {
				rawRules[line] = struct{}{}
			}
			mu.Unlock()
			return nil
		})
	}
	_ = eg.Wait()
	return rules, casSet, rawRules
}

func validateFile(path string, filterCasino, isExcludeFile, isRpz, isDomain bool) ([]DomainRule, map[string]struct{}, map[string]struct{}) {
	var rules []DomainRule
	casSet := make(map[string]struct{})
	rawRules := make(map[string]struct{})

	file, err := os.Open(path)
	if err != nil {
		return rules, casSet, rawRules
	}
	defer file.Close()

	var reader io.Reader = file
	header := make([]byte, 2)
	if n, err := file.Read(header); err == nil && n == 2 {
		if header[0] == 0x1f && header[1] == 0x8b {
			_, _ = file.Seek(0, io.SeekStart)
			gzReader, err := gzip.NewReader(file)
			if err == nil {
				defer gzReader.Close()
				reader = gzReader
			} else {
				_, _ = file.Seek(0, io.SeekStart)
			}
		} else {
			_, _ = file.Seek(0, io.SeekStart)
		}
	} else {
		_, _ = file.Seek(0, io.SeekStart)
	}

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		if idx := strings.IndexByte(line, '#'); idx != -1 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		if isRpz {
			if strings.HasPrefix(line, "$") || strings.HasPrefix(line, "@") {
				continue
			}
			rawRules[line] = struct{}{}
			continue
		}
		if isDomain {
			line = strings.Trim(line, "!\"#$%&'()+,-/:;<=>?@[\\]^_`{|}~")
			if line == "" {
				continue
			}

			fields := strings.Fields(line)
			for _, field := range fields {
				if _, err := netip.ParseAddr(field); err == nil {
					continue
				}
				v := normalizeDomain(field)
				if v != "" {
					if filterCasino && IsCasino(v) {
						casSet[v] = struct{}{}
					} else {
						rules = append(rules, DomainRule{Domain: v, IsEx: isExcludeFile})
					}
				}
			}
			continue
		}
		if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}

		parsed := parseAdblockLine(line, isExcludeFile)
		if parsed != nil {
			v := parsed.Domain
			if filterCasino && IsCasino(v) {
				casSet[v] = struct{}{}
			} else {
				rules = append(rules, *parsed)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Info("COMPILER", "Warning: scanner error reading %s: %v", path, err)
	}
	return rules, casSet, rawRules
}

func parseAdblockLine(line string, forceException bool) *DomainRule {
	line = strings.TrimSpace(line)
	if line == "" || strings.Contains(line, "##") || strings.Contains(line, "#@#") {
		return nil
	}

	isEx := forceException
	var domain string

	if strings.HasPrefix(line, "@@||") {
		isEx = true
		domain = line[4:]
	} else if strings.HasPrefix(line, "||") {
		isEx = false
		domain = line[2:]
	} else if strings.HasPrefix(line, "@@") {
		isEx = true
		domain = line[2:]
	} else {
		domain = line
	}

	checkDomain := domain
	hasWildcard := false
	if strings.HasPrefix(checkDomain, "*.") {
		checkDomain = checkDomain[2:]
		hasWildcard = true
	}

	if strings.Contains(domain, "/") {
		return nil
	}

	idx := strings.IndexAny(checkDomain, "^$*")
	if idx != -1 {
		checkDomain = checkDomain[:idx]
	}

	if hasWildcard {
		domain = "*." + checkDomain
	} else {
		domain = checkDomain
	}

	domain = strings.TrimSpace(domain)
	if domain == "" || (strings.Contains(domain, "*") && !strings.HasPrefix(domain, "*.")) {
		return nil
	}

	v := normalizeDomain(domain)
	if v == "" {
		return nil
	}
	return &DomainRule{Domain: v, IsEx: isEx}
}

func stripPrefixesMap(src map[string]struct{}) map[string]struct{} {
	res := make(map[string]struct{})
	for d := range src {
		res[stripPrefix(d)] = struct{}{}
	}
	return res
}

func writeRPZFile(path string, domains []string, excl []string, rawRules []string, routeAll bool) {
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		logger.Error("COMPILER", "Failed to create temp RPZ file %s: %v", tmpPath, err)
		return
	}

	bw := bufio.NewWriterSize(f, 64*1024)

	_, _ = bw.WriteString(fmt.Sprintf("$TTL 10800\n@ SOA . . (%d 1 1 1 10800)\n", time.Now().Unix()))
	if routeAll && strings.Contains(path, "proxy") {
		_, _ = bw.WriteString("* CNAME .\n")
	}

	for _, r := range rawRules {
		_, _ = bw.WriteString(r + "\n")
	}

	sort.Strings(excl)
	for _, d := range excl {
		if d != "" && d != "." {
			_, _ = bw.WriteString(fmt.Sprintf("%s. CNAME rpz-passthru.\n*.%s. CNAME rpz-passthru.\n", d, d))
		}
	}

	sort.Strings(domains)
	for _, d := range domains {
		if d != "" && d != "." {
			_, _ = bw.WriteString(fmt.Sprintf("%s. CNAME .\n*.%s. CNAME .\n", d, d))
		}
	}

	if err := bw.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		logger.Error("COMPILER", "Failed to flush RPZ file %s: %v", tmpPath, err)
		return
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		logger.Error("COMPILER", "Failed to sync RPZ file %s: %v", tmpPath, err)
		return
	}

	_ = f.Close()

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		logger.Error("COMPILER", "Failed to rename temp RPZ file %s to %s: %v", tmpPath, path, err)
		return
	}
}

func loadIPs(cfg CompileConfig, name string) ([]netip.Prefix, error) {
	var urls []string
	sourcesFile := filepath.Join(cfg.SourcesDir, name+".txt")
	urls, _ = readUrls(sourcesFile)

	var nets []netip.Prefix
	var mu sync.Mutex

	manFile := filepath.Join(cfg.ManualDir, name+".txt")
	if parsed := parseIPFile(manFile); parsed != nil {
		nets = append(nets, parsed...)
	}

	downloadDir := cfg.DownloadDir
	if downloadDir == "" {
		downloadDir = "/app/nextpath/download"
	}

	var eg errgroup.Group
	eg.SetLimit(10)
	for _, u := range urls {
		u := u
		eg.Go(func() error {
			cachedFile := getCachedFilepath(downloadDir, u, name)
			if _, err := os.Stat(cachedFile); err != nil {
				if err := downloadOrGetCached(downloadDir, u, name); err != nil {
					logger.Warn("COMPILER", "\033[1;33mWarning:\033[0m failed to download %s: %v", u, err)
				}
			}
			if parsed := parseIPFile(cachedFile); parsed != nil {
				mu.Lock()
				nets = append(nets, parsed...)
				mu.Unlock()
			}
			return nil
		})
	}
	_ = eg.Wait()

	return nets, nil
}

func parseIPFile(path string) []netip.Prefix {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var res []netip.Prefix
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		idx := strings.IndexByte(line, '#')
		var ipPart string
		if idx != -1 {
			ipPart = strings.TrimSpace(line[:idx])
		} else {
			ipPart = line
		}

		if ipPart == "" {
			continue
		}
		if !strings.Contains(ipPart, "/") {
			if strings.Contains(ipPart, ":") {
				ipPart += "/128"
			} else {
				ipPart += "/32"
			}
		}
		prefix, err := netip.ParsePrefix(ipPart)
		if err == nil {
			res = append(res, prefix)
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Info("COMPILER", "Warning: scanner error reading IP file %s: %v", path, err)
	}
	return res
}

type IPCompileResult struct {
	V4RawRoutes  int
	V4ExcRoutes  int
	V4AggrRoutes int
	V6RawRoutes  int
	V6ExcRoutes  int
	V6AggrRoutes int
	V4RawDeny    int
	V4AggrDeny   int
	V6RawDeny    int
	V6AggrDeny   int
}

func compileIPs(cfg CompileConfig, incIps, excIps, denyIps []netip.Prefix) IPCompileResult {
	var res IPCompileResult
	for _, ver := range []int{4, 6} {
		isV6 := ver == 6

		nets := filterIPNets(incIps, isV6, true)
		exNets := filterIPNets(excIps, isV6, false)
		dnNets := filterIPNets(denyIps, isV6, false)

		resDeny := subNetsOptimized(dnNets, nil, isV6)
		writeIPFile(filepath.Join(cfg.ResultDir, fmt.Sprintf("deny-ips-v%d.txt", ver)), resDeny)
		if ver == 4 {
			res.V4RawDeny = len(dnNets)
			res.V4AggrDeny = len(resDeny)
		} else {
			res.V6RawDeny = len(dnNets)
			res.V6AggrDeny = len(resDeny)
		}
		logger.Debug("COMPILER", "Compiling deny-ips-v%d.txt...", ver)

		exCombined := append(exNets, dnNets...)

		aggrNets := aggregatePrefixes(nets, cfg.Limit, isV6)
		resRoutes := subNetsOptimized(aggrNets, exCombined, isV6)

		aggrRoutes := resRoutes
		writeIPFile(filepath.Join(cfg.ResultDir, fmt.Sprintf("route-ips-v%d.txt", ver)), aggrRoutes)
		if ver == 4 {
			res.V4RawRoutes = len(nets)
			res.V4ExcRoutes = len(exCombined)
			res.V4AggrRoutes = len(aggrRoutes)
		} else {
			res.V6RawRoutes = len(nets)
			res.V6ExcRoutes = len(exCombined)
			res.V6AggrRoutes = len(aggrRoutes)
		}
		logger.Debug("COMPILER", "Compiling route-ips-v%d.txt...", ver)
	}
	return res
}

func aggregatePrefixes(nets []netip.Prefix, limit int, isV6 bool) []netip.Prefix {
	if len(nets) == 0 {
		return nets
	}
	if limit <= 0 {
		return nets
	}
	res := collapseIPNets(nets, isV6)
	if len(res) <= limit {
		return res
	}

	for len(res) > limit {
		maxPrefix := -1
		for _, n := range res {
			if n.Bits() > maxPrefix {
				maxPrefix = n.Bits()
			}
		}

		minPrefix := 12
		if isV6 {
			minPrefix = 32
		}

		if maxPrefix <= minPrefix {
			break
		}

		var supers []netip.Prefix
		for _, n := range res {
			if n.Bits() == maxPrefix {
				p, err := n.Addr().Prefix(maxPrefix - 1)
				if err == nil {
					supers = append(supers, p.Masked())
				} else {
					supers = append(supers, n)
				}
			} else {
				supers = append(supers, n)
			}
		}
		res = collapseIPNets(supers, isV6)
	}

	return res
}

func filterIPNets(src []netip.Prefix, isV6 bool, applySafeguard bool) []netip.Prefix {
	var res []netip.Prefix

	minAllowedV4 := 4
	minAllowedV6 := 16

	for _, n := range src {
		if n.Addr().Is6() == isV6 {
			if applySafeguard && ((!isV6 && n.Bits() < minAllowedV4) || (isV6 && n.Bits() < minAllowedV6)) {
				logger.Error("COMPILER", "Safeguard triggered: ignoring excessively wide subnet %s", n.String())
				continue
			}
			res = append(res, n)
		}
	}
	return res
}

func writeIPFile(path string, nets []netip.Prefix) {
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		logger.Error("COMPILER", "Failed to create temp IP file %s: %v", tmpPath, err)
		return
	}

	bw := bufio.NewWriterSize(f, 64*1024)

	for _, n := range nets {
		if _, err := bw.WriteString(n.String() + "\n"); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			logger.Error("COMPILER", "Failed to write to temp IP file %s: %v", tmpPath, err)
			return
		}
	}

	if err := bw.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		logger.Error("COMPILER", "Failed to flush temp IP file %s: %v", tmpPath, err)
		return
	}

	_ = f.Close()

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		logger.Error("COMPILER", "Failed to rename temp IP file %s to %s: %v", tmpPath, path, err)
		return
	}
}

func subNetsOptimized(incNets, excNets []netip.Prefix, isV6 bool) []netip.Prefix {
	var builder netipx.IPSetBuilder
	for _, n := range incNets {
		builder.AddPrefix(n)
	}
	for _, n := range excNets {
		builder.RemovePrefix(n)
	}
	s, _ := builder.IPSet()
	return s.Prefixes()
}

func collapseIPNets(nets []netip.Prefix, isV6 bool) []netip.Prefix {
	return subNetsOptimized(nets, nil, isV6)
}

func readUrls(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls, nil
}

func uniqueSliceFromMap(src map[string]struct{}) []string {
	res := make([]string, 0, len(src))
	for s := range src {
		res = append(res, s)
	}
	sort.Strings(res)
	return res
}

type domainSorter []string

func (s domainSorter) Len() int      { return len(s) }
func (s domainSorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s domainSorter) Less(i, j int) bool {
	a, b := s[i], s[j]
	la, lb := len(a), len(b)
	for k := 1; k <= la && k <= lb; k++ {
		ca, cb := a[la-k], b[lb-k]
		if ca != cb {
			return ca < cb
		}
	}
	return la < lb
}

func CollapseDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}

	sort.Sort(domainSorter(domains))

	optimized := domains[:0]
	var currentSuffix string

	for i, d := range domains {
		if i == 0 || !strings.HasSuffix(d, currentSuffix) {
			currentSuffix = "." + d
			optimized = append(optimized, d)
		}
	}

	return optimized
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")

	if strings.ContainsAny(d, "[]~:/?#\\@!$&'()*+,;=") {
		return ""
	}
	d = strings.Trim(d, ".")
	if !strings.Contains(d, ".") || len(d) > 253 {
		return ""
	}

	asciiDomain, err := idna.ToASCII(d)
	if err != nil {
		return ""
	}
	d = asciiDomain

	labels := strings.Split(d, ".")
	for _, label := range labels {
		if !isValidLabel(label) {
			return ""
		}
	}

	return d
}

func isValidLabel(label string) bool {
	l := len(label)
	if l == 0 || l > 63 {
		return false
	}
	if !isAlnumOrU(label[0]) || !isAlnumOrU(label[l-1]) {
		return false
	}
	for i := 1; i < l-1; i++ {
		c := label[i]
		if !isAlnumOrU(c) && c != '-' {
			return false
		}
	}
	return true
}

func isAlnumOrU(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func stripPrefix(d string) string {
	if strings.Count(d, ".") >= 2 {
		dLower := strings.ToLower(d)
		firstDot := strings.IndexByte(dLower, '.')
		if firstDot > 0 {
			prefix := dLower[:firstDot]
			if isNumberedPrefix(prefix, "www") ||
				isNumberedPrefix(prefix, "m") ||
				isNumberedPrefix(prefix, "hd") ||
				isNumberedPrefix(prefix, "cdn") ||
				isPureDigits(prefix) {
				return d[firstDot+1:]
			}
		}
	}
	return d
}

func isNumberedPrefix(s, base string) bool {
	if !strings.HasPrefix(s, base) {
		return false
	}
	rest := s[len(base):]
	if len(rest) == 0 {
		return true
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	return true
}

func isPureDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func getStateHash(cfg CompileConfig, fileType string) string {
	h := sha256.New()

	downloadDir := cfg.DownloadDir
	if downloadDir == "" {
		downloadDir = "/app/nextpath/download"
	}

	var files []string
	for _, dir := range []string{cfg.SourcesDir, cfg.ManualDir, downloadDir} {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".txt") {
				if fileType == "ips" {
					if strings.Contains(info.Name(), "-ips.txt") || strings.Contains(path, "/include-ips/") || strings.Contains(path, "/exclude-ips/") {
						files = append(files, path)
					}
				} else if fileType == "domains" {
					if !strings.Contains(info.Name(), "-ips.txt") && !strings.Contains(path, "/include-ips/") && !strings.Contains(path, "/exclude-ips/") {
						files = append(files, path)
					}
				}
			}
			return nil
		})
	}

	sort.Strings(files)

	for _, f := range files {
		h.Write([]byte(filepath.Base(f)))
		if info, err := os.Stat(f); err == nil {
			h.Write([]byte(fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())))
		}
	}

	h.Write([]byte(fmt.Sprintf("ROUTE_ALL=%v", cfg.RouteAll)))
	h.Write([]byte(fmt.Sprintf("FILTER_CASINO=%v", cfg.FilterCasino)))
	h.Write([]byte(fmt.Sprintf("LIMIT=%d", cfg.Limit)))
	h.Write([]byte(fmt.Sprintf("BLOCK_ADS=%v", cfg.BlockAds)))
	h.Write([]byte(fmt.Sprintf("ENABLE_IPV6=%v", cfg.EnableIPv6)))
	h.Write([]byte(fmt.Sprintf("IPV6_PROXY_ONLY=%s", os.Getenv("IPV6_PROXY_ONLY"))))
	h.Write([]byte(fmt.Sprintf("NEXTPATH_DNS_IP=%s", os.Getenv("NEXTPATH_DNS_IP"))))
	h.Write([]byte(fmt.Sprintf("FAKE_IP=%s", os.Getenv("FAKE_IP"))))
	h.Write([]byte(fmt.Sprintf("FAKE_IP6=%s", os.Getenv("FAKE_IP6"))))

	return hex.EncodeToString(h.Sum(nil))
}

func getCachedFilepath(downloadDir, url, stem string) string {
	h := md5.Sum([]byte(url))
	hashStr := hex.EncodeToString(h[:])[:8]
	return filepath.Join(downloadDir, stem, hashStr+".txt")
}

func downloadOrGetCached(downloadDir, url, stem string) error {
	cachedFile := getCachedFilepath(downloadDir, url, stem)
	metaFile := cachedFile + ".meta"
	_ = os.MkdirAll(filepath.Dir(cachedFile), 0755)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	if fileExists(cachedFile) {
		if meta, err := os.ReadFile(metaFile); err == nil {
			parts := strings.SplitN(string(meta), "\n", 2)
			if len(parts) == 2 {
				if etag := strings.TrimSpace(parts[0]); etag != "" {
					req.Header.Set("If-None-Match", etag)
				}
				if lastMod := strings.TrimSpace(parts[1]); lastMod != "" {
					req.Header.Set("If-Modified-Since", lastMod)
				}
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("COMPILER", "Network error downloading %s: %v", url, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		logger.Debug("COMPILER", "Cache up-to-date (304 Not Modified): %s", url)
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", cachedFile, time.Now().UnixNano())
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	written, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		return err
	}

	if written == 0 {
		logger.Warn("COMPILER", "\033[1;33mWarning:\033[0m empty body from %s, skipping cache write", url)
		return nil
	}

	if err := os.Rename(tmpFile, cachedFile); err != nil {
		return err
	}

	etag := resp.Header.Get("ETag")
	lastMod := resp.Header.Get("Last-Modified")
	if etag != "" || lastMod != "" {
		_ = os.WriteFile(metaFile, []byte(etag+"\n"+lastMod), 0644)
	} else {
		_ = os.Remove(metaFile)
	}

	logger.Debug("COMPILER", "Downloaded and updated cache: %s", url)
	return nil
}

func downloadSources(cfg CompileConfig) {
	downloadDir := cfg.DownloadDir
	if downloadDir == "" {
		downloadDir = "/app/nextpath/download"
	}
	_ = os.MkdirAll(downloadDir, 0755)

	var files []string
	_ = filepath.Walk(cfg.SourcesDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".txt") {
			files = append(files, path)
		}
		return nil
	})

	var eg errgroup.Group
	eg.SetLimit(10)

	activeCachedFiles := make(map[string]bool)
	seenUrls := make(map[string]bool)
	var activeMu sync.Mutex

	for _, f := range files {
		stem := strings.TrimSuffix(filepath.Base(f), ".txt")
		urls, err := readUrls(f)
		if err != nil {
			continue
		}
		for _, url := range urls {
			cachedPath := getCachedFilepath(downloadDir, url, stem)
			activeMu.Lock()
			activeCachedFiles[cachedPath] = true
			if seenUrls[cachedPath] {
				activeMu.Unlock()
				continue
			}
			seenUrls[cachedPath] = true
			activeMu.Unlock()

			url := url
			stem := stem
			eg.Go(func() error {
				_ = downloadOrGetCached(downloadDir, url, stem)
				return nil
			})
		}
	}
	_ = eg.Wait()

	_ = filepath.Walk(downloadDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".txt") {
			if !activeCachedFiles[path] {
				_ = os.Remove(path)
				_ = os.Remove(path + ".meta")
			}
		}
		return nil
	})
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Size() > 0
}
