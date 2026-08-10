package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB
var ServerSecret string

func init() {
	ServerSecret = os.Getenv("SERVER_SECRET")
	if ServerSecret == "" {
		log.Fatal("❌ SERVER_SECRET environment variable is not set!")
	}
	if len(ServerSecret) < 32 {
		log.Fatal("❌ SERVER_SECRET is too short! Use at least 32-64 random characters.")
	}
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "licenses.db")
	if err != nil {
		log.Fatal(err)
	}

	db.Exec(`CREATE TABLE IF NOT EXISTS licenses (
		key TEXT PRIMARY KEY,
		expiry TEXT,
		status TEXT DEFAULT 'AVAILABLE',
		hwid TEXT DEFAULT '',
		desktop_name TEXT DEFAULT '',
		ip TEXT DEFAULT '',
		activated_at TEXT DEFAULT ''
	)`)

	// Migrate old tables
	db.Exec(`ALTER TABLE licenses ADD COLUMN desktop_name TEXT DEFAULT ''`)
	db.Exec(`ALTER TABLE licenses ADD COLUMN ip TEXT DEFAULT ''`)
	db.Exec(`ALTER TABLE licenses ADD COLUMN activated_at TEXT DEFAULT ''`)
}

func loadKeysFromTxt() {
	data, err := os.ReadFile("keys.txt")
	if err != nil {
		log.Println("keys.txt not found – starting empty")
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
		status := "AVAILABLE"
		hwid := ""
		if len(parts) >= 3 {
			status = strings.TrimSpace(parts[2])
		}
		if len(parts) >= 4 {
			hwid = strings.TrimSpace(parts[3])
		}
		db.Exec(`INSERT OR IGNORE INTO licenses (key, expiry, status, hwid) VALUES (?, ?, ?, ?)`,
			key, expiry, status, hwid)
	}
	log.Println("✅ Keys loaded from keys.txt")
}

func updateKeysTxt(key, expiry, status, hwid string) {
	data, _ := os.ReadFile("keys.txt")
	lines := strings.Split(string(data), "\n")
	newLines := []string{}
	found := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+"|") {
			nl := key + "|" + expiry
			if status != "" {
				nl += "|" + status
			}
			if hwid != "" {
				nl += "|" + hwid
			}
			newLines = append(newLines, nl)
			found = true
		} else if trimmed != "" {
			newLines = append(newLines, line)
		}
	}
	if !found {
		nl := key + "|" + expiry
		if status != "" {
			nl += "|" + status
		}
		if hwid != "" {
			nl += "|" + hwid
		}
		newLines = append(newLines, nl)
	}
	os.WriteFile("keys.txt", []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

func removeKeyFromTxt(key string) {
	data, err := os.ReadFile("keys.txt")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	newLines := []string{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, key+"|") && trimmed != "" {
			newLines = append(newLines, line)
		}
	}
	os.WriteFile("keys.txt", []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

func signResponse(data map[string]any) string {
	jsonBytes, _ := json.Marshal(data)
	mac := hmac.New(sha256.New, []byte(ServerSecret))
	mac.Write(jsonBytes)
	return hex.EncodeToString(mac.Sum(nil))
}

func generateKey() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	rand.Read(b)
	key := "TARZFN-"
	for i := 0; i < 15; i++ {
		if i > 0 && i%5 == 0 {
			key += "-"
		}
		key += string(charset[int(b[i])%len(charset)])
	}
	return key
}

func checkAdmin(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+ServerSecret
}

func enableCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

func getClientIP(r *http.Request) string {
	// Cloudflare / Render / proxies
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- VALIDATE ----------
func validateHandler(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Key         string `json:"key"`
		HWID        string `json:"hwid"`
		DesktopName string `json:"desktop_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Invalid request"})
		return
	}

	var expiry, status, storedHWID, desktopName, ip, activatedAt string
	err := db.QueryRow(`SELECT expiry, status, hwid, desktop_name, ip, activated_at 
		FROM licenses WHERE key = ?`, req.Key).
		Scan(&expiry, &status, &storedHWID, &desktopName, &ip, &activatedAt)

	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Invalid or unregistered key"})
		return
	}

	if status == "REVOKED" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Key revoked"})
		return
	}

	// HWID lock
	if storedHWID != "" && storedHWID != req.HWID && storedHWID != "UNBOUND" {
		json.NewEncoder(w).Encode(map[string]any{"valid": false, "message": "Key already bound to another PC"})
		return
	}

	// First-time activation → store everything
	if storedHWID == "" || storedHWID == "UNBOUND" {
		clientIP := getClientIP(r)
		now := time.Now().UTC().Format("2006-01-02 15:04:05")

		desktop := req.DesktopName
		if desktop == "" {
			desktop = req.HWID // fallback
		}

		db.Exec(`UPDATE licenses SET 
			hwid = ?, desktop_name = ?, ip = ?, activated_at = ?, status = 'ACTIVE'
			WHERE key = ?`,
			req.HWID, desktop, clientIP, now, req.Key)

		updateKeysTxt(req.Key, expiry, "ACTIVE", req.HWID)
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

	response := map[string]any{
		"valid":     true,
		"expiry":    expiry,
		"message":   "Success",
		"timestamp": time.Now().Unix(),
	}
	response["signature"] = signResponse(response)
	json.NewEncoder(w).Encode(response)
}

// ---------- ADMIN API ----------
func adminList(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	if !checkAdmin(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}

	rows, err := db.Query(`SELECT key, expiry, status, hwid, desktop_name, ip, activated_at 
		FROM licenses ORDER BY key`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	type L struct {
		Key         string `json:"key"`
		Expiry      string `json:"expiry"`
		Status      string `json:"status"`
		HWID        string `json:"hwid"`
		DesktopName string `json:"desktop_name"`
		IP          string `json:"ip"`
		ActivatedAt string `json:"activated_at"`
		DaysLeft    any    `json:"days_left"`
		IsExpired   bool   `json:"is_expired"`
	}

	var list []L
	now := time.Now().UTC()

	for rows.Next() {
		var l L
		rows.Scan(&l.Key, &l.Expiry, &l.Status, &l.HWID, &l.DesktopName, &l.IP, &l.ActivatedAt)

		if strings.Contains(strings.ToUpper(l.Expiry), "LIFETIME") {
			l.DaysLeft = "Lifetime"
		} else {
			exp, err := time.Parse("20060102", l.Expiry)
			if err == nil {
				days := int(exp.Sub(now).Hours() / 24)
				l.DaysLeft = days
				l.IsExpired = days < 0
			} else {
				l.DaysLeft = "?"
			}
		}
		list = append(list, l)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func adminCreate(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	if !checkAdmin(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Key    string `json:"key"`
		Expiry string `json:"expiry"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Key == "" {
		req.Key = generateKey()
	}
	if req.Expiry == "" {
		req.Expiry = "LIFETIME"
	}

	db.Exec(`INSERT OR REPLACE INTO licenses 
		(key, expiry, status, hwid, desktop_name, ip, activated_at) 
		VALUES (?, ?, 'AVAILABLE', '', '', '', '')`, req.Key, req.Expiry)

	updateKeysTxt(req.Key, req.Expiry, "AVAILABLE", "")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "key": req.Key, "expiry": req.Expiry})
}

func adminDelete(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	if !checkAdmin(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct{ Key string `json:"key"` }
	json.NewDecoder(r.Body).Decode(&req)
	if req.Key == "" {
		http.Error(w, "missing key", 400)
		return
	}

	db.Exec("DELETE FROM licenses WHERE key = ?", req.Key)
	removeKeyFromTxt(req.Key)
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func adminUnbind(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	if !checkAdmin(r) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct{ Key string `json:"key"` }
	json.NewDecoder(r.Body).Decode(&req)
	if req.Key == "" {
		http.Error(w, "missing key", 400)
		return
	}

	var expiry string
	db.QueryRow("SELECT expiry FROM licenses WHERE key = ?", req.Key).Scan(&expiry)

	db.Exec(`UPDATE licenses SET 
		hwid = '', desktop_name = '', ip = '', activated_at = '', status = 'AVAILABLE' 
		WHERE key = ?`, req.Key)

	updateKeysTxt(req.Key, expiry, "AVAILABLE", "")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func main() {
	initDB()
	loadKeysFromTxt()

	http.HandleFunc("/validate", validateHandler)
	http.HandleFunc("/admin/list", adminList)
	http.HandleFunc("/admin/create", adminCreate)
	http.HandleFunc("/admin/delete", adminDelete)
	http.HandleFunc("/admin/unbind", adminUnbind)

	fmt.Println("✅ Server Running - Secure License System Active")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
