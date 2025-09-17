package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"example.com/go-rest-jwt/internal/auth"
)

// Auth middleware validates JWT from Authorization: Bearer <token>
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Context().Value(userKey).(string))

		h := r.Header.Get("Authorization")
		if h == "" || !strings.HasPrefix(strings.ToLower(h), "bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimSpace(h[len("Bearer "):])
		claims, err := auth.ParseAndValidate(tok)
		if err != nil {
			http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "uid", claims.Sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
