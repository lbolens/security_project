package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("postgres", "user=admin password=secret123 dbname=mydb")
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/user", getUserHandler)
	http.HandleFunc("/search", searchHandler)

	log.Println("Server starting on :8080")
	http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil)
}

// SQL Injection vulnerability - string concatenation
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")

	// VULNERABLE: SQL Injection
	query := "SELECT * FROM users WHERE id = ?"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	fmt.Fprintf(w, "User data retrieved")
}

// Another SQL Injection vulnerability
func searchHandler(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("q")

	// VULNERABLE: SQL Injection
	query := "SELECT * FROM products WHERE name LIKE ?"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	fmt.Fprintf(w, "Search results")
}
