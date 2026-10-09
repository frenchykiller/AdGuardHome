package home

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/aghuser"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	oidcProvider     *oidc.Provider
	oidcOauth2Config oauth2.Config
	oidcVerifier     *oidc.IDTokenVerifier
	oidcEnabled      bool
	oidcAdminGroup   string
	oidcGroupsClaim  string
)

func initOIDC(ctx context.Context) error {
	issuer := os.Getenv("OIDC_ISSUER")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURI := os.Getenv("OIDC_REDIRECT_URI")
	adminGroup := os.Getenv("OIDC_ADMIN_GROUP")
	groupsClaim := os.Getenv("OIDC_GROUPS_CLAIM")

	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil // OIDC not configured
	}

	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to get provider: %v", err)
	}

	oidcProvider = provider
	oidcOauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	oidcVerifier = provider.Verifier(&oidc.Config{ClientID: clientID})
	oidcEnabled = true
	oidcAdminGroup = adminGroup
	oidcGroupsClaim = groupsClaim
	return nil
}

func (web *webAPI) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled {
		aghhttp.ErrorAndLog(r.Context(), web.logger, r, w, http.StatusNotFound, "OIDC is not enabled")
		return
	}

	state := "random-state-123"
	http.Redirect(w, r, oidcOauth2Config.AuthCodeURL(state), http.StatusFound)
}

func (web *webAPI) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !oidcEnabled {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusNotFound, "OIDC is not enabled")
		return
	}

	if r.URL.Query().Get("state") != "random-state-123" {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusBadRequest, "Invalid state")
		return
	}

	code := r.URL.Query().Get("code")
	oauth2Token, err := oidcOauth2Config.Exchange(ctx, code)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "Failed to exchange token")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "No id_token field in oauth2 token")
		return
	}

	idToken, err := oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "Failed to verify ID Token")
		return
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "Failed to parse claims")
		return
	}

	// Fetch optional claims
	userInfo, err := oidcProvider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err == nil {
		var userInfoClaims map[string]interface{}
		if err := userInfo.Claims(&userInfoClaims); err == nil {
			for k, v := range userInfoClaims {
				if _, ok := claims[k]; !ok {
					claims[k] = v
				}
			}
		}
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		email, ok = claims["preferred_username"].(string)
		if !ok || email == "" {
			email = "oidc_user"
		}
	}

	if oidcAdminGroup != "" {
		groupsInterface, ok := claims[oidcGroupsClaim]
		if !ok {
			aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusForbidden, "Missing groups claim")
			return
		}

		hasGroup := false
		switch groups := groupsInterface.(type) {
		case []interface{}:
			for _, g := range groups {
				if g == oidcAdminGroup {
					hasGroup = true
					break
				}
			}
		case string:
			hasGroup = groups == oidcAdminGroup
		}

		if !hasGroup {
			aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusForbidden, "User does not have admin group")
			return
		}
	}

	user, err := web.auth.users.ByLogin(ctx, aghuser.Login(email))
	if err != nil {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "Error checking user")
		return
	}
	if user == nil {
		wu := &webUser{Name: email}
		err = web.auth.addUser(ctx, wu, "OIDC_MANAGED_PASSWORD_DO_NOT_USE")
		if err != nil {
			aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "Failed to create user")
			return
		}
		user, err = web.auth.users.ByLogin(ctx, aghuser.Login(email))
		if err != nil || user == nil {
			aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "Failed to retrieve newly created user")
			return
		}
	}

	sess, err := web.auth.sessions.New(ctx, user)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, web.logger, r, w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    hex.EncodeToString(sess.Token[:]),
		Path:     "/",
		Expires:  idToken.Expiry,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusFound)
}
