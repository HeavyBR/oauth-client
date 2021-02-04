package client

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func GetOpenIDClient(ctx context.Context, clientID, clientSecret, providerURL string) (*oidc.IDTokenVerifier, *oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, providerURL)

	if err != nil {
		return &oidc.IDTokenVerifier{}, &oauth2.Config{}, errors.New(fmt.Sprintf("Something went wrong in provider build process: %s", err.Error()))
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	verifier := provider.Verifier(oidcConfig)

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:8000/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return verifier, config, nil
}