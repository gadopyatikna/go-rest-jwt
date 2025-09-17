package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"example.com/go-rest-jwt/internal/auth"
	"example.com/go-rest-jwt/internal/models"
)

type API struct {
	mu    sync.RWMutex
	users map[string]models.User // by email
}

func NewAPI() *API {
	return &API{
		users: make(map[string]models.User),
	}
}

func (a *API) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"status":"ok"}`)
}

type signupReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (a *API) Signup(w http.ResponseWriter, r *http.Request) {
	var req signupReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password required", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.users[req.Email]; ok {
		http.Error(w, "email already registered", http.StatusConflict)
		return
	}
	salt := randomHex(16)
	hashed := hash(req.Password, salt)
	u := models.User{
		ID:       fmt.Sprintf("u_%d", time.Now().UnixNano()),
		Email:    req.Email,
		Password: hashed,
		Salt:     salt,
		Name:     req.Name,
	}
	a.users[req.Email] = u
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id": u.ID, "email": u.Email, "name": u.Name})
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	u, err := a.getUser(req.Email)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if u.Password != hash(req.Password, u.Salt) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	claims := auth.Claims{
		Sub: u.ID,
		Exp: auth.Expiry(30 * time.Minute),
	}
	tok, err := auth.Sign(claims)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"access_token": tok, "token_type": "Bearer"})
}

func (a *API) Me(w http.ResponseWriter, r *http.Request) {
	uid := r.Context().Value("uid")
	if uid == nil {
		http.Error(w, "missing context", http.StatusInternalServerError)
		return
	}
	// find user by ID
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, u := range a.users {
		if u.ID == uid.(string) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"id":    u.ID,
				"email": u.Email,
				"name":  u.Name,
			})
			return
		}
	}
	http.Error(w, "user not found", http.StatusNotFound)
}

func (a *API) getUser(email string) (models.User, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	u, ok := a.users[email]
	if !ok {
		return models.User{}, errors.New("not found")
	}
	return u, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hash(pass, salt string) string {
	h := sha256.Sum256([]byte(salt + ":" + pass))
	return hex.EncodeToString(h[:])
}
