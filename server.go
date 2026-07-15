package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB
var ServerSecret string

// ==================== CONFIG ====================
func init() {
	ServerSecret = os.Getenv("SERVER_SECRET")
	if ServerSecret == "" {
		log.Fatal("❌ SERVER_SECRET environment variable is not set!")
	}
	if len(ServerSecret) < 32 {
		log.Fatal("❌ SERVER_SECRET is too short! Use at least 32-64 random characters.")
	}
}

// ===============================================

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

func loadKeysFromTxt() {
	data, err := os.ReadFile("keys.txt")
	if err != nil {
		log.Println("❌ keys.txt not found!")
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		expiry := strings.TrimSpace(parts[1])

		db.Exec("INSERT OR REPLACE INTO licenses (key, expiry, status) VALUES (?, ?, 'AVAILABLE')", key, expiry)
	}
	log.Println("✅ Keys loaded from keys.txt")
}

func updateKeysTxt(key, expiry, status, hwid string) {
	data, err := os.ReadFile("keys.txt")
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	newLines := []string{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+"|") {
			newLine := key + "|" + expiry
			if status != "" {
				newLine += "|" + status
			}
			if hwid != "" {
				newLine += "|" + hwid
			}
			newLines = append(newLines, newLine)
		} else {
			newLines = append(newLines, line)
		}
	}

	os.WriteFile("keys.txt", []byte(strings.Join(newLines, "\n")), 0644)
	log.Println("✅ Updated keys.txt for key:", key)
}

// signResponse creates HMAC signature
func signResponse(data map[string]any) string {
	jsonBytes, _ := json.Marshal(data)
	mac := hmac.New(sha256.New, []byte(ServerSecret))
	mac.Write(jsonBytes)
	return hex.EncodeToString(mac.Sum(nil))
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

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Invalid request"})
		return
	}

	var expiry, status, storedHWID string
	err := db.QueryRow("SELECT expiry, status, hwid FROM licenses WHERE key = ?", req.Key).
		Scan(&expiry, &status, &storedHWID)

	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Invalid or unregistered key"})
		return
	}

	if status == "REVOKED" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Key revoked"})
		return
	}

	// HWID Check
	if storedHWID != "" && storedHWID != req.HWID && storedHWID != "UNBOUND" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Key already bound to another PC"})
		return
	}

	// Auto-activate & bind
	newStatus := "ACTIVE"
	if storedHWID == "" || storedHWID == "UNBOUND" {
		db.Exec("UPDATE licenses SET hwid = ?, status = ? WHERE key = ?", req.HWID, newStatus, req.Key)
		updateKeysTxt(req.Key, expiry, newStatus, req.HWID)
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

	// === Build signed response ===
	response := map[string]any{
		"valid":     true,
		"expiry":    expiry,
		"message":   "Success",
		"timestamp": time.Now().Unix(),
	}

	response["signature"] = signResponse(response)

	json.NewEncoder(w).Encode(response)
}

func main() {
	initDB()
	loadKeysFromTxt()

	http.HandleFunc("/validate", validateHandler)

	fmt.Println("✅ Server Running - Secure License System Active")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
