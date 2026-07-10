package main

import (
	"database/sql"
	"fmt"
	_ "modernc.org/sqlite"
	"strings"
)

func main() {
	db, _ := sql.Open("sqlite", "licenses.db")
	defer db.Close()

	// Add as many keys as you want here
	keys := []string{
		"OND-FN-LT-4LX12Q|LIFETIME|AVAILABLE",
		"OND-FN-TEST-ABC123|20271231|AVAILABLE",
		"OND-FN-30DAYS-XYZ|30DAYS|AVAILABLE",
		// Add more lines here...
	}

	for _, line := range keys {
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		expiry := strings.TrimSpace(parts[1])

		_, err := db.Exec("INSERT OR REPLACE INTO licenses (key, expiry, status) VALUES (?, ?, 'AVAILABLE')", key, expiry)
		if err == nil {
			fmt.Println("✅ Added:", key, "|", expiry)
		}
	}

	fmt.Println("\nAll keys added successfully!")
}
