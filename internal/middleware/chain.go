package middleware

import (
	"net/http"
)

// Chain takes a final handler and wraps it with multiple middlewares
func Chain(h http.HandlerFunc, mws ...func(http.Handler) http.Handler) http.Handler {
	var handler http.Handler = h
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}
	return handler
}
