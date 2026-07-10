package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "licenses.db")
	if err != nil {
		log.Fatal(err)
	}

	db.Exec(`CREATE TABLE IF NOT EXISTS licenses (
		key TEXT PRIMARY KEY,
		expiry TEXT,
		status TEXT DEFAULT "AVAILABLE",
		hwid TEXT DEFAULT ""
	)`)
}

func validateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Key  string `json:"key"`
		HWID string `json:"hwid"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Key == "" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Invalid key"})
		return
	}

	var expiry, status, storedHWID string
	err := db.QueryRow("SELECT expiry, status, hwid FROM licenses WHERE key = ?", req.Key).Scan(&expiry, &status, &storedHWID)

	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Invalid or unregistered key"})
		return
	}

	if status == "REVOKED" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Key has been revoked"})
		return
	}

	// HWID Check
	if storedHWID != "" && storedHWID != req.HWID && storedHWID != "UNBOUND" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Key already bound to another PC"})
		return
	}

	// Bind if not bound
	if storedHWID == "" || storedHWID == "UNBOUND" {
		db.Exec("UPDATE licenses SET hwid = ?, status = 'ACTIVE' WHERE key = ?", req.HWID, req.Key)
	}

	// Expiry check
	expired := false
	if !strings.Contains(strings.ToUpper(expiry), "LIFETIME") {
		expDate, _ := time.Parse("20060102", expiry)
		if !expDate.IsZero() && time.Now().UTC().After(expDate) {
			expired = true
		}
	}

	if expired {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "License expired"})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"valid":  true,
		"expiry": expiry,
		"message": "Success",
	})
}

func main() {
	initDB()
	defer db.Close()

	http.HandleFunc("/validate", validateHandler)

	fmt.Println("✅ Server Running")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
