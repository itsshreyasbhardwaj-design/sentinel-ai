// Intentionally insecure fixture for Sentinel AI's test suite. Do not deploy.
package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func getUser(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// SQL injection via Sprintf.
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}

func runShell(userCmd string) {
	// Command executed through a shell.
	exec.Command("/bin/sh", "-c", userCmd).Run()
}

func insecureClient() *http.Client {
	// TLS verification disabled.
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
