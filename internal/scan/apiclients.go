package scan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/warrox1993/clawkwerk/internal/scope"
)

// Clients API de référence (UniFi, Sophos). ÉCRITS D'APRÈS LA DOCUMENTATION,
// NON validés contre un contrôleur/boîtier réel : les endpoints et le format
// des réponses sont à confirmer au banc. Toutes les requêtes sont en LECTURE
// (login + GET / requête de consultation) ; aucune n'écrit de configuration.

// --- Ubiquiti UniFi (contrôleur) ---
//
// UniFi n'expose aucune CLI de configuration pare-feu : la seule source est
// l'API du contrôleur UniFi Network. Flux : POST /api/login (cookie de session)
// puis GET de la ressource REST demandée.
type UniFiClient struct {
	Site string // "default" par défaut
}

func NewUniFiClient() *UniFiClient { return &UniFiClient{Site: "default"} }

func (c *UniFiClient) Platform() string { return "unifi" }

func (c *UniFiClient) Fetch(ctx context.Context, host scope.ScopedHost, cred *scope.Credential, resource string, hc *http.Client) ([]byte, error) {
	port := host.Port
	if port == 0 {
		port = 8443
	}
	base := "https://" + host.Address + ":" + strconv.Itoa(port)

	// 1) Authentification (POST JSON) — dépose un cookie de session dans le jar.
	loginBody := fmt.Sprintf(`{"username":%q,"password":%q}`, cred.Username, string(cred.Secret()))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/login", bytes.NewBufferString(loginBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login UniFi : %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login UniFi : statut %d", resp.StatusCode)
	}

	// 2) Récupération de la ressource (ex. "firewall" -> règles de pare-feu).
	endpoint := "/api/s/" + c.Site + "/rest/firewallrule"
	if resource != "" && resource != "firewall" {
		endpoint = "/api/s/" + c.Site + "/rest/" + resource
	}
	return httpGet(ctx, hc, base+endpoint)
}

// --- Sophos Firewall (API XML) ---
//
// Sophos Firewall s'administre par une API XML sur le port 4444 : on POST un
// document reqxml contenant l'authentification et une requête Get<Entité>.
type SophosClient struct{}

func NewSophosClient() *SophosClient { return &SophosClient{} }

func (c *SophosClient) Platform() string { return "sophosxg" }

func (c *SophosClient) Fetch(ctx context.Context, host scope.ScopedHost, cred *scope.Credential, resource string, hc *http.Client) ([]byte, error) {
	port := host.Port
	if port == 0 {
		port = 4444
	}
	entity := "FirewallRule"
	if resource != "" && resource != "firewall" {
		entity = resource
	}
	// Requête XML de CONSULTATION (Get) — ne modifie rien.
	reqxml := fmt.Sprintf(
		`<Request><Login><Username>%s</Username><Password>%s</Password></Login><Get><%s></%s></Get></Request>`,
		cred.Username, string(cred.Secret()), entity, entity)
	url := "https://" + host.Address + ":" + strconv.Itoa(port) + "/webconsole/APIController?reqxml=" + reqxml
	return httpGet(ctx, hc, url)
}

// httpGet effectue un GET et renvoie le corps (lecture seule).
func httpGet(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s : statut %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // borne 4 Mo (garde-fou)
}
