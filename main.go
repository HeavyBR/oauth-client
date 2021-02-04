package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/heavybr/oauth-client/pkg/client"
	"github.com/heavybr/oauth-client/pkg/routes"
	"github.com/joho/godotenv"
	"golang.org/x/net/context"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	ctx := context.Background()

	r := mux.NewRouter()

	setupEnvironment()

	var clientID, clientSecret, providerURL string

	provider := flag.String("provider", "", "use oauth0 or google as provider")
	flag.Parse()

	if *provider == "oauth0" {
		clientID     = os.Getenv("OAUTH0_CLIENT_ID")
		clientSecret = os.Getenv("OAUTH0_CLIENT_SECRET")
		providerURL  = os.Getenv("OAUTH0_PROVIDER_URL")

	} else if *provider == "google" {
		clientID     = os.Getenv("GOOGLE_CLIENT_ID")
		clientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
		providerURL  = os.Getenv("GOOGLE_PROVIDER_URL")

	} else {
		log.Fatal("choose between google or oauth0")
	}


	verifier, config, err := client.GetOpenIDClient(ctx, clientID, clientSecret, providerURL)

	if err != nil {
		log.Fatal(err.Error())
	}

	state := uuid.NewString()

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

	r.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: " + err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}


		resp := struct {
			AccessToken string `json:"access_token"`
			TokenType string `json:"token_type,omitempty"`
			Expiry time.Time `json:"expiry,omitempty"`
			IDToken string `json:"id_token,omitempty"`
		}{oauth2Token.AccessToken, oauth2Token.TokenType, oauth2Token.Expiry, rawIDToken}


		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	})

	r.HandleFunc("/whoami", func (w http.ResponseWriter, r *http.Request) {
		idToken := r.Header.Get("id_token")
		accessToken := r.Header.Get("access_token")


		if idToken == "" {
			http.Error(w, "you must provide an id_token", http.StatusUnauthorized)
			return
		}

		token, err := verifier.Verify(ctx, idToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: " + err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{new(json.RawMessage)}

		if err := token.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(resp)
		err = token.VerifyAccessToken(accessToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	}).Methods("POST")


	r.HandleFunc("/auth/logout", routes.LogoutHandler).Methods("GET")


	log.Printf("listening on http://%s/", "127.0.0.1:8000")
	log.Fatal(http.ListenAndServe("127.0.0.1:8000", r))
}

func setupEnvironment() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal("fail to read .env file")
	}

}