package main

import (
	webauthn "Justin-del/WebAuthn/WebAuthn"
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {

	http.HandleFunc("POST /register/options", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		username := req.Username

		session_identifier, options := webauthn.GetPublicKeyCredentialCreationOptions("", "required", "required", []webauthn.Credential{}, 1000*60*5, []string{}, username)

		optionsJSON, err := json.Marshal(options)
		if err != nil {
			http.Error(w, "Failed to marshal options", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_identifier",
			Value:    session_identifier,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(optionsJSON))
	})

	http.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_identifier")
		if err != nil {
			http.Error(w, "Session identifier cookie not found", http.StatusUnauthorized)
			return
		}
		session_id := cookie.Value

		var cred webauthn.RegistrationPublicKeyCredential
		if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		fmt.Println(session_id)
		fmt.Println(cred.Response.Transports)
		// fmt.Println(webauthn.RegisterPublicKeyCredential(session_id, cred, "http://localhost:8080"))

		w.Header().Set("Content-Type", "application/json")
	})

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
