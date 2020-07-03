package providers

import (
	"context"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

type KeycloakProvider struct {
	*ProviderData
	Group string
}

var _ Provider = (*KeycloakProvider)(nil)

const (
	keycloakProviderName = "Keycloak"
	keycloakDefaultScope = "api"
)

var (
	// Default Login URL for Keycloak.
	// Pre-parsed URL of https://keycloak.org/oauth/authorize.
	keycloakDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/oauth/authorize",
	}

	// Default Redeem URL for Keycloak.
	// Pre-parsed URL of ttps://keycloak.org/oauth/token.
	keycloakDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/oauth/token",
	}

	// Default Validation URL for Keycloak.
	// Pre-parsed URL of https://keycloak.org/api/v3/user.
	keycloakDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/api/v3/user",
	}
)

func NewKeycloakProvider(p *ProviderData) *KeycloakProvider {
	p.setProviderDefaults(keycloakProviderName, keycloakDefaultLoginURL, keycloakDefaultRedeemURL, nil, keycloakDefaultValidateURL, keycloakDefaultScope)
	return &KeycloakProvider{ProviderData: p}
}

func (p *KeycloakProvider) SetGroup(group string) {
	p.Group = group
}

func (p *KeycloakProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {

	req, err := http.NewRequestWithContext(ctx, "GET", p.ValidateURL.String(), nil)
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	json, err := requests.Request(req)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	if p.Group != "" {
		var groups, err = json.Get("groups").Array()
		if err != nil {
			logger.Printf("groups not found %s", err)
			return "", err
		}

		var found = false
		for i := range groups {
			if groups[i].(string) == p.Group {
				found = true
				break
			}
		}

		if !found {
			logger.Printf("group not found, access denied")
			return "", nil
		}
	}

	return json.Get("email").String()
}
