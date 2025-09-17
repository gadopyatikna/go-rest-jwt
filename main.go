package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"example.com/go-rest-jwt/internal/handlers"
	"example.com/go-rest-jwt/internal/middleware"
)

func main() {
	addr := ":8080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}

	// Basic server with http.ServeMux
	mux := http.NewServeMux()
	api := handlers.NewAPI()

	mux.HandleFunc("GET /health", api.Health)
	mux.HandleFunc("POST /signup", api.Signup)
	mux.HandleFunc("POST /login", api.Login)

	// Protected routes
	mux.Handle("GET /me", middleware.Log(middleware.Auth(http.HandlerFunc(api.Me))))

	srv := &http.Server{
		Addr:              addr,
		Handler:           logging(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

// simple access log
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
