package main

import (
	"nextpath/internal/logger"
	"os"
	"strconv"
	"strings"
	"time"

	"nextpath/internal/parser"
)

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
	val := strings.ToLower(getEnv(key, ""))
	if val == "" {
		return defaultVal
	}
	return val == "true" || val == "1" || val == "y" || val == "yes"
}

func main() {
	logger.Init(getEnvBool("DEBUG", false))
	logger.Info("COMPILER-CLI", "Starting list compilation...")
	startTime := time.Now()

	limit := 500
	limitStr := getEnv("AGGREGATE_COUNT", "")
	if limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil {
			limit = val
		}
	}

	cfg := parser.CompileConfig{
		SourcesDir:   getEnv("SOURCES_DIR", "/app/nextpath/lists/sources"),
		ManualDir:    getEnv("MANUAL_DIR", "/app/nextpath/lists/manual"),
		ResultDir:    getEnv("RESULT_DIR", "/app/nextpath/result"),
		DownloadDir:  getEnv("DOWNLOAD_DIR", "/app/nextpath/download"),
		RouteAll:     getEnvBool("ROUTE_ALL", false),
		FilterCasino: getEnvBool("FILTER_CASINO", true),
		BlockAds:     getEnvBool("BLOCK_ADS", true),
		EnableIPv6:   getEnvBool("ENABLE_IPV6", true),
		Limit:        limit,
	}

	err := parser.CompileLists(cfg)
	if err != nil {
		logger.Error("COMPILER-CLI", "Critical Error: %v", err)
		os.Exit(1)
	}

	logger.Info("COMPILER-CLI", "Successfully compiled lists in %v!", time.Since(startTime))
}
