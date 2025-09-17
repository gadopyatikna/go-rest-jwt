package models

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"` // stored as salted hash (demo-only)
	Salt     string `json:"-"`
	Name     string `json:"name"`
}
