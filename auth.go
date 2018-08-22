package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/knq/jwt"
	"golang.org/x/crypto/bcrypt"
)

// LoginInput request body.
type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginPayload respond body.
type LoginPayload struct {
	AuthUser  User      `json:"authUser"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// OK checks for semantic errors.
func (input LoginInput) OK() (map[string]string, bool) {
	errs := make(map[string]string)

	input.Email = strings.TrimSpace(input.Email)
	if input.Email == "" {
		errs["email"] = "email required"
	} else if !rxEmail.MatchString(input.Email) {
		errs["email"] = "invalid email"
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

const tokenLifespan = time.Hour * 24 * 365 // One year

func loginUser(w http.ResponseWriter, r *http.Request) {
	// Decode request body
	defer r.Body.Close()
	var input LoginInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if errs, ok := input.OK(); !ok {
		respondJSON(w, errs, http.StatusUnprocessableEntity)
		return
	}

	// Find user on the database with the email and password
	var user User
	if err := db.QueryRowContext(r.Context(), `
		SELECT id, username, hashed_password, created_at
		FROM users
		WHERE email = $1
	`, input.Email).Scan(
		&user.ID,
		&user.Username,
		&user.HashedPassword,
		&user.CreatedAt,
	); err == sql.ErrNoRows {
		fmt.Println("not found:", err)
		http.Error(w,
			http.StatusText(http.StatusNotFound),
			http.StatusNotFound)
		return
	} else if err != nil {
		respondError(w, err)
		return
	}

	user.Email = input.Email
	bytePassword := []byte(input.Password)
	hashedBytePassword := []byte(user.HashedPassword)

	log.Println(user)

	err := bcrypt.CompareHashAndPassword(hashedBytePassword, bytePassword)
	if err != nil {
		http.Error(w, fmt.Sprintf("wrong password: %v", err), http.StatusUnprocessableEntity)
		return
	}

	// Isuer a JWT
	token, exp, err := issueToken(user.ID)
	if err != nil {
		respondError(w, err)
		return
	}

	// Respond with the JWT
	http.SetCookie(w, createTokenCookie(token, exp))

	log.Println(user)

	respondJSON(w, LoginPayload{
		AuthUser:  user,
		Token:     token,
		ExpiresAt: exp,
	}, http.StatusOK)
}

func issueToken(userID string) (token string, exp time.Time, err error) {
	exp = time.Now().Add(tokenLifespan)
	t, err := jwtSigner.Encode(jwt.Claims{
		Subject:    userID,
		Expiration: json.Number(strconv.FormatInt(exp.Unix(), 10)),
	})
	if err != nil {
		return "", exp, err
	}
	return string(t), exp, nil
}

func createTokenCookie(token string, exp time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
	}
}
