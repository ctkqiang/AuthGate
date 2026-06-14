// Package service (server.go) provides the unified local HTTP server and
// the shared route table consumed by all cloud-runtime adapters.
//
// Every environment — local development, AWS Lambda, Aliyun FC — uses the
// single [Routes] slice so that adding or changing an endpoint in one place
// takes effect everywhere.
package service

import (
	"authgate/internal/model"
	"authgate/internal/utilities"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

const (
	// Addr is the local development listen address.
	Addr = "0.0.0.0:8080"

	// IndexPath  is the root health-check endpoint.
	IndexPath = "/"
	// HealthPath is the /health liveness probe endpoint.
	HealthPath = "/health"
)

// RouteEntry pairs a URL path with its handler function.  The [Routes]
// slice is the single source of truth for all runtime adapters.
type RouteEntry struct {
	Path    string
	Handler http.HandlerFunc
}

// Routes is the shared route table used by the local server, AWS Lambda
// handler, and Aliyun FC handler.  Add new endpoints here to make them
// available in every environment.
var Routes = []RouteEntry{
	{Path: IndexPath, Handler: model.Index},
	{Path: HealthPath, Handler: model.Health},
}

// IsLocalMode reports whether none of the supported cloud runtimes
// are detected, meaning we should start the local development server.
func IsLocalMode() bool {
	_, lambdaPort := os.LookupEnv("_LAMBDA_SERVER_PORT")
	_, lambdaAPI := os.LookupEnv("AWS_LAMBDA_RUNTIME_API")
	_, fcFunc := os.LookupEnv("FC_FUNCTION_NAME")

	onAWS := lambdaPort && lambdaAPI
	onAliyun := fcFunc

	return !onAWS && !onAliyun
}

// StartLocalServer starts a single net/http server on [Addr] with graceful
// shutdown on SIGINT / SIGTERM.  This function blocks until the server
// stops.
func StartLocalServer() {
	utilities.LogProgress("HTTP", "Starting local server", Addr)

	mux := http.NewServeMux()
	for _, entry := range Routes {
		mux.HandleFunc(entry.Path, logRequest(entry.Handler))
	}

	srv := &http.Server{Addr: Addr, Handler: mux}

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		utilities.LogProgress("HTTP", "Shutting down gracefully", "signal received")
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		utilities.Error("HTTP server failed: %v", err)
	}
}

// logRequest wraps an http.HandlerFunc with a request log line.
func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		utilities.LogProgress(
			"http",
			r.Method+" "+r.URL.Path,
			fmt.Sprintf("source=%s", r.RemoteAddr),
		)
		next(w, r)
	}
}