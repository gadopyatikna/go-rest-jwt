package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

// HS256 JWT (minimal) using only stdlib.
// NOT for production as-is (no kid/alg checks against header spoofing etc.).

var defaultSecret = []byte("dev-secret-change-me")

func secret() []byte {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return []byte(s)
	}
	return defaultSecret
}

type Claims struct {
	Sub string `json:"sub"` // subject / user ID
	Exp int64  `json:"exp"` // unix seconds
}

// base64url without padding (RFC 7515)
func b64(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func ub64(s string) ([]byte, error) {
	// restore padding if needed
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func Sign(claims Claims) (string, error) {
	header := map[string]string{"typ": "JWT", "alg": "HS256"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)

	seg := b64(hb) + "." + b64(cb)
	mac := hmac.New(sha256.New, secret())
	mac.Write([]byte(seg))
	sig := mac.Sum(nil)
	return seg + "." + b64(sig), nil
}

func ParseAndValidate(token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, errors.New("invalid token format")
	}
	seg := parts[0] + "." + parts[1]

	// verify signature
	sigBytes, err := ub64(parts[2])
	if err != nil {
		return c, errors.New("invalid signature encoding")
	}
	mac := hmac.New(sha256.New, secret())
	mac.Write([]byte(seg))
	expected := mac.Sum(nil)
	if !hmac.Equal(sigBytes, expected) {
		return c, errors.New("signature mismatch")
	}

	// decode claims
	cb, err := ub64(parts[1])
	if err != nil {
		return c, errors.New("invalid claims encoding")
	}
	if err := json.Unmarshal(cb, &c); err != nil {
		return c, errors.New("invalid claims")
	}
	// check exp
	if c.Exp != 0 && time.Now().Unix() > c.Exp {
		return c, errors.New("token expired")
	}
	return c, nil
}

// Helper to build exp
func Expiry(d time.Duration) int64 {
	return time.Now().Add(d).Unix()
}
