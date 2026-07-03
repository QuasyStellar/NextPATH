package parser

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParser_CompileListsCachingAndUpdates(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nextpath-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sourcesDir := filepath.Join(tempDir, "sources")
	manualDir := filepath.Join(tempDir, "manual")
	resultDir := filepath.Join(tempDir, "result")
	downloadDir := filepath.Join(tempDir, "download")

	_ = os.MkdirAll(sourcesDir, 0755)
	_ = os.MkdirAll(manualDir, 0755)

	var mockBody = "domain1.com\ndomain2.com\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := md5.Sum([]byte(mockBody))
		etag := hex.EncodeToString(h[:])
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockBody))
	}))
	defer server.Close()

	sourceFile := filepath.Join(sourcesDir, "include-hosts.txt")
	err = os.WriteFile(sourceFile, []byte(server.URL+"\n"), 0644)
	if err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	cfg := CompileConfig{
		SourcesDir:   sourcesDir,
		ManualDir:    manualDir,
		ResultDir:    resultDir,
		DownloadDir:  downloadDir,
		RouteAll:     false,
		FilterCasino: false,
		BlockAds:     false,
		EnableIPv6:   false,
		Limit:        100,
	}

	err = CompileLists(cfg)
	if err != nil {
		t.Fatalf("First compilation failed: %v", err)
	}

	rpzPath := filepath.Join(resultDir, "proxy.rpz")
	data1, err := os.ReadFile(rpzPath)
	if err != nil {
		t.Fatalf("Failed to read proxy.rpz: %v", err)
	}
	if !strings.Contains(string(data1), "domain1.com") || !strings.Contains(string(data1), "domain2.com") {
		t.Errorf("proxy.rpz does not contain expected domains: %s", string(data1))
	}

	var cacheCreated bool
	_ = filepath.Walk(downloadDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".txt") {
			cacheCreated = true
		}
		return nil
	})
	if !cacheCreated {
		t.Errorf("No cache files created in DownloadDir: %s", downloadDir)
	}

	err = os.WriteFile(rpzPath, []byte("overwritten-marker"), 0644)
	if err != nil {
		t.Fatalf("failed to edit proxy.rpz: %v", err)
	}

	err = CompileLists(cfg)
	if err != nil {
		t.Fatalf("Second compilation failed: %v", err)
	}

	data2, err := os.ReadFile(rpzPath)
	if err != nil {
		t.Fatalf("failed to read proxy.rpz: %v", err)
	}
	if string(data2) != "overwritten-marker" {
		t.Errorf("Compilation was executed when it should have been skipped! Got: %s", string(data2))
	}

	mockBody = "domain1.com\ndomain2.com\ndomain3.com\n"

	err = CompileLists(cfg)
	if err != nil {
		t.Fatalf("Third compilation failed: %v", err)
	}

	data3, err := os.ReadFile(rpzPath)
	if err != nil {
		t.Fatalf("failed to read proxy.rpz: %v", err)
	}
	if !strings.Contains(string(data3), "domain3.com") {
		t.Errorf("Compilation did not execute or update the domain list. Got: %s", string(data3))
	}
}

func BenchmarkCollapseDomains(b *testing.B) {
	domains := []string{
		"example.com",
		"sub.example.com",
		"test.com",
		"another.test.com",
		"foo.bar.com",
		"bar.com",
		"google.com",
		"mail.google.com",
		"something.else",
		"abc.something.else",
	}

	for i := 0; i < 5; i++ {
		domains = append(domains, domains...)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CollapseDomains(domains)
	}
}

func TestParser_AggregatePrefixes(t *testing.T) {

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("192.168.2.0/24"),
		netip.MustParsePrefix("192.168.3.0/24"),
	}

	res := aggregatePrefixes(prefixes, 1, false)
	if len(res) > 1 {
		t.Errorf("Expected 1 prefix, got %d", len(res))
	}
}

func parseCIDR(s string) netip.Prefix {
	prefix, _ := netip.ParsePrefix(s)
	return prefix
}

func TestParser_SubNetsOptimized(t *testing.T) {
	inc := []netip.Prefix{
		parseCIDR("10.0.0.0/24"),
		parseCIDR("10.0.1.0/24"),
	}
	exc := []netip.Prefix{
		parseCIDR("10.0.0.128/25"),
	}

	res := subNetsOptimized(inc, exc, false)
	if len(res) == 0 {
		t.Fatalf("subNetsOptimized returned empty result")
	}
}

func TestParser_CollapseIPNets(t *testing.T) {
	nets := []netip.Prefix{
		parseCIDR("192.168.0.0/24"),
		parseCIDR("192.168.1.0/24"),
		parseCIDR("192.168.2.0/24"),
		parseCIDR("192.168.3.0/24"),
	}

	res := collapseIPNets(nets, false)
	if len(res) != 1 {
		t.Errorf("Expected 1 supernet (192.168.0.0/22), got %d", len(res))
	}
}

func TestParser_IsCasinoMatches(t *testing.T) {
	matches := []string{
		"casino-online.com",
		"vulkan-slots.ru",
		"eldorado-club.xyz",
		"Leonbet.ru",
		"my-vulkan-casino.org",
		"1x-bet.com",
		"vulkanization.org",
	}

	for _, d := range matches {
		if !IsCasino(d) {
			t.Errorf("Expected domain %s to match casino filter, but it did not", d)
		}
	}
}

func TestParser_IsCasinoNonMatches(t *testing.T) {
	nonMatches := []string{
		"google.com",
		"betterment.com",
		"poker-club.com",
		"bet.com",
	}

	for _, d := range nonMatches {
		if IsCasino(d) {
			t.Errorf("Expected domain %s NOT to match casino filter, but it did", d)
		}
	}
}
