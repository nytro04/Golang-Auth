package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	rxEmail    = regexp.MustCompile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")
	rxUsername = regexp.MustCompile("^[a-zA-Z][\\w|-]{0,17}$")
)

// CreateUserInput request body.
type CreateUserInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// User model.
type User struct {
	ID             string    `json:"id,omitempty"`
	Username       string    `json:"username"`
	Email          string    `json:"email,omitempty"`
	HashedPassword string    `json:"-"`
	CreatedAt      time.Time `json:"createdAt"`
}

// OK checks for semantic errors.
func (input CreateUserInput) OK() (map[string]string, bool) {
	errs := make(map[string]string)

	input.Email = strings.TrimSpace(input.Email)
	if input.Email == "" {
		errs["email"] = "email required"
	} else if !rxEmail.MatchString(input.Email) {
		errs["email"] = "invalid email"
	}

	input.Username = strings.TrimSpace(input.Username)
	if input.Username == "" {
		errs["username"] = "username required"
	} else if !rxUsername.MatchString(input.Username) {
		errs["username"] = "invalid username"
	}

	input.Password = strings.TrimSpace(input.Password)
	if input.Password == "" {
		errs["password"] = "password required"
	}

	if len(errs) != 0 {
		return errs, false
	}

	return nil, true
}

func createUser(w http.ResponseWriter, r *http.Request) {
	// Decode request body
	defer r.Body.Close()
	var input CreateUserInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Input validation
	if errs, ok := input.OK(); !ok {
		respondJSON(w, errs, http.StatusUnprocessableEntity)
		return
	}

	// Hash and salt password with bcrypt
	hashedPasswordByte, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, fmt.Errorf("could not hash password: %v", err))
		return
	}
	hashedPassword := string(hashedPasswordByte)

	var user User
	// Inser user into db
	err = db.QueryRowContext(r.Context(), `
		INSERT INTO users (username, email, hashed_password) VALUES ($1, $2, $3)
		RETURNING id, created_at
	`, input.Username, input.Email, hashedPassword).Scan(
		&user.ID,
		&user.CreatedAt,
	)
	if errPq, ok := err.(*pq.Error); ok && errPq.Code.Name() == "unique_violation" {
		if strings.Contains(errPq.Error(), "email") {
			respondJSON(w, map[string]string{"email": "email taken"}, http.StatusConflict)
		} else {
			respondJSON(w, map[string]string{"username": "username taken"}, http.StatusConflict)
		}
		return
	}
	if err != nil {
		respondError(w, err)
		return
	}

	user.Email = input.Email
	user.Username = input.Username

	// Isuer a JWT
	token, exp, err := issueToken(user.ID)
	if err != nil {
		respondError(w, err)
		return
	}

	// Respond with the JWT
	http.SetCookie(w, createTokenCookie(token, exp))

	// Repond with Created user
	respondJSON(w, user, http.StatusCreated)
}
