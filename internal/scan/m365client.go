package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"projetcyber/internal/scope"
)

// Microsoft365Client interroge Microsoft Graph en LECTURE SEULE pour un tenant
// M365, via le flux OAuth2 client-credentials (app-registration read-only fournie
// par le client). C'est un APIClient (plateforme "m365") : il réutilise APISource
// et ses garde-fous (journal requis, cred requis) et n'émet JAMAIS d'écriture Graph.
//
// STATUT : écrit d'après la doc Graph (schémas officiels stables), NON validé
// contre un vrai tenant. Le flux HTTP/OAuth n'est pas testé ; seul le PARSING des
// réponses (controls.ParseM365MFA / ParseM365Inventory) l'est. À valider en pilote.
//
// Le Credential encode l'app-registration : Username = "<tenantID>:<clientID>",
// Secret() = le client secret (jamais sérialisé).
type Microsoft365Client struct{}

func (Microsoft365Client) Platform() string { return "m365" }

const graphBase = "https://graph.microsoft.com/v1.0"

// Fetch récupère l'enveloppe de réponses Graph pour une ressource logique
// ("mfa" → PR.AA-03.2 ; "inventory" → ID.AM). Uniquement des GET (+ le POST du
// jeton OAuth, qui ne modifie rien).
func (c Microsoft365Client) Fetch(ctx context.Context, host scope.ScopedHost, cred *scope.Credential, resource string, hc *http.Client) ([]byte, error) {
	if cred == nil {
		return nil, fmt.Errorf("m365: credential requis (app-registration read-only)")
	}
	tenant, clientID, ok := strings.Cut(cred.Username, ":")
	if !ok || tenant == "" || clientID == "" {
		return nil, fmt.Errorf(`m365: Username attendu au format "tenantID:clientID"`)
	}
	token, err := c.token(ctx, hc, tenant, clientID, string(cred.Secret()))
	if err != nil {
		return nil, err
	}
	switch resource {
	case "mfa":
		sd, err := c.get(ctx, hc, token, "/policies/identitySecurityDefaultsEnforcementPolicy")
		if err != nil {
			return nil, err
		}
		ca, err := c.get(ctx, hc, token, "/identity/conditionalAccess/policies")
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]json.RawMessage{"security_defaults": sd, "conditional_access": ca})
	case "inventory":
		sk, err := c.get(ctx, hc, token, "/subscribedSkus")
		if err != nil {
			return nil, err
		}
		dm, err := c.get(ctx, hc, token, "/domains")
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]json.RawMessage{"subscribed_skus": sk, "domains": dm})
	default:
		return nil, fmt.Errorf("m365: ressource inconnue %q", resource)
	}
}

// token exécute le flux OAuth2 client-credentials (aucune modification du tenant).
func (Microsoft365Client) token(ctx context.Context, hc *http.Client, tenant, clientID, secret string) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	endpoint := "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("m365: obtention du jeton : %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("m365: jeton refusé (HTTP %d)", resp.StatusCode)
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &t); err != nil || t.AccessToken == "" {
		return "", fmt.Errorf("m365: jeton illisible")
	}
	return t.AccessToken, nil
}

// get émet un GET Graph authentifié (lecture seule).
func (Microsoft365Client) get(ctx context.Context, hc *http.Client, token, path string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, graphBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("m365: GET %s : %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("m365: GET %s (HTTP %d)", path, resp.StatusCode)
	}
	return json.RawMessage(body), nil
}
