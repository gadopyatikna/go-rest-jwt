# Go REST API with JWT (net/http, no frameworks)

A minimal REST service written in Go using the standard library only:
- Routing with `http.ServeMux`
- JWT HS256 implemented via `crypto/hmac` (no external deps)
- In-memory user store (demo only)
- Endpoints: `/health`, `/signup`, `/login`, `/me`

## Requirements
- Go 1.22+
- Set `JWT_SECRET` (optional; defaults to `dev-secret-change-me`)

## Run
```bash
# inside the repo root
go run .
# or change port
ADDR=":9090" go run .
```

## Build
```bash
go build -o app .
./app
```

## API

### Health
```
GET /health -> 200 {"status":"ok"}
```

### Signup
```
POST /signup
Content-Type: application/json

{
  "email": "alice@example.com",
  "password": "s3cret",
  "name": "Alice"
}
```
Response `200`:
```json
{"id":"u_...","email":"alice@example.com","name":"Alice"}
```

### Login
```
POST /login
Content-Type: application/json

{
  "email": "alice@example.com",
  "password": "s3cret"
}
```
Response `200`:
```json
{"access_token":"<JWT>","token_type":"Bearer"}
```

### Me (protected)
```
GET /me
Authorization: Bearer <JWT>
```
Response `200`:
```json
{"id":"u_...","email":"alice@example.com","name":"Alice"}
```

## cURL demo

```bash
# 1) start server
go run . &

# 2) signup
curl -s localhost:8080/signup -d '{"email":"a@ex.com","password":"p","name":"Alice"}' -H 'content-type: application/json'

# 3) login
TOKEN=$(curl -s localhost:8080/login -d '{"email":"a@ex.com","password":"p"}' -H 'content-type: application/json' | jq -r .access_token)

# 4) me
curl -s localhost:8080/me -H "authorization: Bearer $TOKEN" | jq .
```

## Notes
- This is a demo; the password hashing uses salted SHA-256 for zero dependencies.
  Use a proper password KDF like bcrypt/argon2 in production.
- This JWT implementation is intentionally minimal; for production, prefer a well-tested library.
