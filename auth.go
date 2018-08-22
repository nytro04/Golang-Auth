package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// User Input request body
type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginPayload respond body
type LoginPayload struct {
	AuthUser  User      `json:"authUser"`
	JWT       string    `json:"jwt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

var jwtKey = env("JWT_KEY", "dontT3ll@ny0ne")

func loginUser(w http.ResponseWriter, r *http.Request) {
	// Decode request body
	var input LoginInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	email := input.Email
	password := input.Password

	// Find user on the database with the email and password
	var user User
	if err := db.QueryRowContext(r.Context(), `
		SELECT id, username, email, hashed_password, created_at
		FROM users
		WHERE email = $1
	`, email).Scan(
		&user.ID,
		&user.Username,
		user.Email,
		&user.Password,
		&user.CreatedAt,
	); err == sql.ErrNoRows {
		http.Error(w,
			http.StatusText(http.StatusNotFound),
			http.StatusNotFound)
		return
	} else if err != nil {
		respondError(w, err)
		return
	}

	bytePassword := []byte(password)
	hashedBytePassword := []byte(user.Password)

	log.Println(user)

	err := bcrypt.CompareHashAndPassword(hashedBytePassword, bytePassword)
	if err != nil {
		respondError(w, fmt.Errorf("Wrong password: %v", err))
		return
	}

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

	log.Println(user)

	respondJSON(w, LoginPayload{user, tokenString, expires}, http.StatusOK)

}
