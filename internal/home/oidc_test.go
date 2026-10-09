package home

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"encoding/json"
	"strings"
	"crypto/rsa"
	"crypto/rand"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"time"
	"github.com/AdguardTeam/AdGuardHome/internal/aghuser"
)

func generateJWK(t *testing.T) (jose.JSONWebKey, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key",
		Algorithm: "RS256",
		Use:       "sig",
	}
	return jwk, privateKey
}

func signJWT(t *testing.T, key *rsa.PrivateKey, issuer, clientID string) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	require.NoError(t, err)

	cl := jwt.Claims{
		Issuer:   issuer,
		Subject:  "test-subject",
		Audience: jwt.Audience{clientID},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	raw, err := jwt.Signed(signer).Claims(cl).Claims(map[string]interface{}{
		"email": "test@example.com",
		"groups": []string{"admin"},
	}).Serialize()
	require.NoError(t, err)

	return raw
}

func mockOIDCServer(t *testing.T, jwk jose.JSONWebKey, priv *rsa.PrivateKey, clientID string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			config := map[string]interface{}{
				"issuer":                                srv.URL,
				"authorization_endpoint":                srv.URL + "/auth",
				"token_endpoint":                        srv.URL + "/token",
				"jwks_uri":                              srv.URL + "/jwks",
				"userinfo_endpoint":                     srv.URL + "/userinfo",
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}
			json.NewEncoder(w).Encode(config)
		case "/jwks":
			jwks := map[string]interface{}{
				"keys": []jose.JSONWebKey{jwk},
			}
			json.NewEncoder(w).Encode(jwks)
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     signJWT(t, priv, srv.URL, clientID),
			})
		case "/userinfo":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"email": "test@example.com",
				"groups": []string{"admin"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv
}

type mockUserDB struct {
	aghuser.DB
}

func (m *mockUserDB) ByLogin(ctx context.Context, login aghuser.Login) (*aghuser.User, error) {
	return nil, nil // Return nil so auto-provisioning happens
}

func (m *mockUserDB) Create(ctx context.Context, u *aghuser.User) error {
	return nil
}

type mockSessionStorage struct {
	aghuser.SessionStorage
}

func (m *mockSessionStorage) New(ctx context.Context, u *aghuser.User) (*aghuser.Session, error) {
	return &aghuser.Session{}, nil
}

func TestOIDCInitAndHandlers(t *testing.T) {
	jwk, priv := generateJWK(t)
	server := mockOIDCServer(t, jwk, priv, "test-client")
	defer server.Close()

	os.Setenv("OIDC_ISSUER", server.URL)
	os.Setenv("OIDC_CLIENT_ID", "test-client")
	os.Setenv("OIDC_CLIENT_SECRET", "test-secret")
	os.Setenv("OIDC_REDIRECT_URI", "http://localhost/callback")
	os.Setenv("OIDC_ADMIN_GROUP", "admin")
	os.Setenv("OIDC_GROUPS_CLAIM", "groups")

	err := initOIDC(context.Background())
	require.NoError(t, err)
	assert.True(t, oidcEnabled)

	web := &webAPI{
		logger: slogutil.NewDiscardLogger(),
		auth: &auth{
			logger: slogutil.NewDiscardLogger(),
			users: &mockUserDB{},
			sessions: &mockSessionStorage{},
		},
	}


	t.Run("LoginRedirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/control/oidc/login", nil)
		w := httptest.NewRecorder()

		web.handleOIDCLogin(w, req)
		assert.Equal(t, http.StatusFound, w.Code)
		loc := w.Header().Get("Location")
		assert.True(t, strings.HasPrefix(loc, server.URL+"/auth"))
	})

	t.Run("CallbackValid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/control/oidc/callback?state=random-state-123&code=123", nil)
		w := httptest.NewRecorder()

		web.handleOIDCCallback(w, req)
	})

	t.Run("CallbackInvalidState", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/control/oidc/callback?state=invalid", nil)
		w := httptest.NewRecorder()

		web.handleOIDCCallback(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("LoginDisabled", func(t *testing.T) {
		oidcEnabled = false
		req := httptest.NewRequest(http.MethodGet, "/control/oidc/login", nil)
		w := httptest.NewRecorder()

		web.handleOIDCLogin(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
		oidcEnabled = true
	})
	
	t.Run("CallbackDisabled", func(t *testing.T) {
		oidcEnabled = false
		req := httptest.NewRequest(http.MethodGet, "/control/oidc/callback", nil)
		w := httptest.NewRecorder()

		web.handleOIDCCallback(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
		oidcEnabled = true
	})
	t.Run("CallbackExchangeFailed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/control/oidc/callback?state=random-state-123&code=badcode", nil)
		w := httptest.NewRecorder()
		web.handleOIDCCallback(w, req)
	})

	t.Run("CallbackNoAdminGroup", func(t *testing.T) {
		os.Setenv("OIDC_ADMIN_GROUP", "superadmin")
		_ = initOIDC(context.Background())
		req := httptest.NewRequest(http.MethodGet, "/control/oidc/callback?state=random-state-123&code=123", nil)
		w := httptest.NewRecorder()
		web.handleOIDCCallback(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
		
		// Reset back
		os.Setenv("OIDC_ADMIN_GROUP", "admin")
		_ = initOIDC(context.Background())
	})
}

