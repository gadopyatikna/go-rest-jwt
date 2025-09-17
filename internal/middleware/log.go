package middleware

import (
	"context"
	"log"
	"net/http"
)

func Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if h == "" {
			log.Println("No auth header provided")
		}

		ctx := context.WithValue(r.Context(), userKey, "logger middleware pu it here")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
