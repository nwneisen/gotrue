package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultGlobalidAuthBase = "api.global.id"
	defaultGlobalidAPIBase  = "api.global.id"
)

type globalidProvider struct {
	*oauth2.Config
	APIPath string
}

type globalidUser struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	AvatarURL     string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"verified_email"`
}

// NewGlobalIdProvider creates a GlobalId account provider.
func NewGlobalidProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultGlobalidAuthBase)
	apiPath := chooseHost(ext.URL, defaultGlobalidAPIBase) + "/userinfo/v2/me"

	oauthScopes := []string{
		"public",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &globalidProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/v1/consent/authentication_request",
				TokenURL: authHost + "/v1/auth/token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g globalidProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g globalidProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u globalidUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath, &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	if u.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    u.Email,
			Verified: u.EmailVerified,
			Primary:  true,
		})
	}

	if len(data.Emails) <= 0 {
		return nil, errors.New("Unable to find email with GlobalId provider")
	}

	data.Metadata = &Claims{
		Issuer:        g.APIPath,
		Subject:       u.ID,
		Name:          u.Name,
		Picture:       u.AvatarURL,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,

		// To be deprecated
		AvatarURL:  u.AvatarURL,
		FullName:   u.Name,
		ProviderId: u.ID,
	}

	return data, nil
}
