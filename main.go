package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/knq/jwt"
)

var (
	jwtSigner jwt.Signer
	db        *sql.DB
)

func env(key, fallbackValue string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallbackValue
	}
	return value
}

func intEnv(key string, fallbackValue int) int {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallbackValue
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return fallbackValue
	}
	return intValue
}

func respondJSON(w http.ResponseWriter, payload interface{}, code int) {
	b, err := json.Marshal(payload)
	if err != nil {
		respondError(w, fmt.Errorf("could not marshal response payload: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write(b)
}

func respondError(w http.ResponseWriter, err error) {
	log.Println(err)
	http.Error(w,
		http.StatusText(http.StatusInternalServerError),
		http.StatusInternalServerError)
}

func main() {
	port := intEnv("PORT", 3000)
	// jwtKey := env("JWT_KEY", "dontT3ll@ny0ne")
	databaseURL := env("DATABASE_URL", "postgresql://root@127.0.0.1:26257/shop_api?sslmode=disable")

	var err error

	if db, err = sql.Open("postgres", databaseURL); err != nil {
		log.Fatalf("could not open database connection: %v\n", err)
		return
	}
	defer db.Close()
	if err = db.Ping(); err != nil {
		log.Fatalf("could not ping database: %v\n", err)
	}

	if jwtSigner, err = jwt.HS256.New([]byte(jwtKey)); err != nil {
		log.Fatalf("could not create JWT signer: %v\n", err)
		return
	}
	mux := mux.NewRouter()

	mux.HandleFunc("/api/users", createUser).Methods("POST")
	mux.HandleFunc("/api/login", loginUser).Methods("POST")

	log.Printf("accepting connections on port: %d\n", port)

	log.Fatalln(http.ListenAndServe(fmt.Sprintf(":%d", port), mux))

}
