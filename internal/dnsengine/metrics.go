package dnsengine

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"nextpath/internal/logger"
)

var (
	MetricsUptimeStart time.Time
	MetricsAllocations atomic.Uint64
	MetricsCollisions  atomic.Uint64
	MetricsSyncs       atomic.Uint64
	MetricsDNSQueries  atomic.Uint64
	MetricsDNSErrors   atomic.Uint64
	MetricsExhaustions atomic.Uint64
)

func init() {
	MetricsUptimeStart = time.Now()
}

func StartMetricsServer(addr string, port string, pool *IPPool) {
	if port == "" {
		port = "9090"
	}
	if addr == "" {
		addr = "0.0.0.0"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		capacity := uint32(0)
		active := 0
		if pool != nil {
			capacity = pool.GetPoolSize()
			active = pool.GetActiveCount()
		}

		uptime := time.Since(MetricsUptimeStart).Seconds()
		allocs := MetricsAllocations.Load()
		collisions := MetricsCollisions.Load()
		syncs := MetricsSyncs.Load()
		dnsQueries := MetricsDNSQueries.Load()
		dnsErrors := MetricsDNSErrors.Load()
		exhaustions := MetricsExhaustions.Load()

		fmt.Fprintf(w, "# HELP nextpath_uptime_seconds Node uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE nextpath_uptime_seconds gauge\n")
		fmt.Fprintf(w, "nextpath_uptime_seconds %f\n", uptime)

		fmt.Fprintf(w, "# HELP nextpath_pool_capacity Total size of the Fake-IP pool\n")
		fmt.Fprintf(w, "# TYPE nextpath_pool_capacity gauge\n")
		fmt.Fprintf(w, "nextpath_pool_capacity %d\n", capacity)

		fmt.Fprintf(w, "# HELP nextpath_pool_active Number of currently active Fake-IP allocations\n")
		fmt.Fprintf(w, "# TYPE nextpath_pool_active gauge\n")
		fmt.Fprintf(w, "nextpath_pool_active %d\n", active)

		fmt.Fprintf(w, "# HELP nextpath_allocations_total Total number of IP allocations performed\n")
		fmt.Fprintf(w, "# TYPE nextpath_allocations_total counter\n")
		fmt.Fprintf(w, "nextpath_allocations_total %d\n", allocs)

		fmt.Fprintf(w, "# HELP nextpath_p2p_collisions_total Total number of P2P mapping collisions detected\n")
		fmt.Fprintf(w, "# TYPE nextpath_p2p_collisions_total counter\n")
		fmt.Fprintf(w, "nextpath_p2p_collisions_total %d\n", collisions)

		fmt.Fprintf(w, "# HELP nextpath_p2p_syncs_total Total number of P2P sync events processed\n")
		fmt.Fprintf(w, "# TYPE nextpath_p2p_syncs_total counter\n")
		fmt.Fprintf(w, "nextpath_p2p_syncs_total %d\n", syncs)

		fmt.Fprintf(w, "# HELP nextpath_dns_queries_total Total number of DNS queries processed\n")
		fmt.Fprintf(w, "# TYPE nextpath_dns_queries_total counter\n")
		fmt.Fprintf(w, "nextpath_dns_queries_total %d\n", dnsQueries)

		fmt.Fprintf(w, "# HELP nextpath_dns_errors_total Total number of DNS queries that resulted in errors\n")
		fmt.Fprintf(w, "# TYPE nextpath_dns_errors_total counter\n")
		fmt.Fprintf(w, "nextpath_dns_errors_total %d\n", dnsErrors)

		fmt.Fprintf(w, "# HELP nextpath_pool_exhaustions_total Total number of times the IP pool was fully exhausted\n")
		fmt.Fprintf(w, "# TYPE nextpath_pool_exhaustions_total counter\n")
		fmt.Fprintf(w, "nextpath_pool_exhaustions_total %d\n", exhaustions)
	})

	bindAddr := fmt.Sprintf("%s:%s", addr, port)
	logger.Info("METRICS", "Prometheus exporter listening on %s", bindAddr)
	go func() {
		if err := http.ListenAndServe(bindAddr, mux); err != nil {
			logger.Error("METRICS", "Prometheus server failed: %v", err)
		}
	}()
}
