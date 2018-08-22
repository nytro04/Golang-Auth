package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	rxEmail    = regexp.MustCompile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")
	rxUsername = regexp.MustCompile("^[a-zA-Z][\\w|-]{0,17}$")
)

// User Input request body
type CreateUserInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// User model
type User struct {
	ID        string    `json:"-"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"createdAt"`
}

func createUser(w http.ResponseWriter, r *http.Request) {
	// Decode request body
	var input CreateUserInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Input validation
	errs := make(map[string]string)
	if input.Email == "" {
		errs["email"] = "Email required"
	} else if !rxEmail.MatchString(input.Email) {
		errs["email"] = "Invalid email"
	}
	if input.Username == "" {
		errs["username"] = "username required"
	} else if !rxUsername.MatchString(input.Username) {
		errs["username"] = "Invalid username"
	}
	if input.Password == "" {
		errs["password"] = "password required"
	}

	if len(errs) != 0 {
		respondJSON(w, errs, http.StatusUnprocessableEntity)
		return
	}

	// Hash and salt password with bcrypt

	email := input.Email
	username := input.Username
	password := input.Password

	hashedPasswordByte, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, fmt.Errorf("could not hash password: %v", err))
		return
	}
	hashedPassword := string(hashedPasswordByte)

	var user User
	// Inser user into db
	err = db.QueryRowContext(r.Context(), `
		INSERT INTO users (username, email, hashed_password) VALUES ($1, $2, $3)
		RETURNING created_at 
	`, email, username, hashedPassword).Scan(
		&user.CreatedAt,
	)
	if errPq, ok := err.(*pq.Error); ok && errPq.Code.Name() == "unique_violation" {
		if strings.Contains(errPq.Error(), "users_email_key") {
			respondJSON(w, map[string]string{
				"email": "Email taken",
			}, http.StatusUnprocessableEntity)
			return
		}
		respondJSON(w, map[string]string{
			"username": "username taken",
		}, http.StatusUnprocessableEntity)
		return
	} else if err != nil {
		respondError(w, err)
		return
	}

	user.Email = email
	user.Username = username
	user.Password = hashedPassword

	// Isuer a JWT
	expires := time.Now().Add(time.Hour * 24 * 365) // one year
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject:   user.ID,
		ExpiresAt: expires.Unix(),
	}).SignedString([]byte(jwtKey))
	if err != nil {
		respondError(w, err)
		return
	}

	// Respond with the JWT
	http.SetCookie(w, &http.Cookie{
		Name:    "jwt",
		Value:   tokenString,
		Path:    "/",
		Expires: expires,
	})

	// Repond with Created user
	respondJSON(w, user, http.StatusCreated)
}
