package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/scope"
)

// APISource collecte la preuve d'un équipement piloté par API (contrôleur UniFi,
// Sophos Firewall…), en LECTURE SEULE. C'est le pendant HTTP des transports
// SSH/WinRM : mêmes garde-fous (journal requis, cred requis, ressource read-
// only), aiguillage par plateforme (HostRef.OS) vers un client constructeur.
//
// STATUT : clients de référence écrits d'après la doc API, NON validés contre un
// contrôleur réel. Le flux HTTP/auth n'est donc pas testé ; seul le parsing des
// réponses (côté normaliseurs) l'est.
type APISource struct {
	clients  map[string]APIClient
	Timeout  time.Duration
	insecure bool // désactive la vérif TLS — LABO uniquement
	now      func() time.Time
}

// APIClient = client HTTP d'un constructeur : il sait s'authentifier et
// récupérer une RESSOURCE (identifiant d'endpoint défini par l'adaptateur du
// contrôle, ex. "firewall"), en LECTURE SEULE. Fetch ne doit jamais modifier
// l'équipement.
type APIClient interface {
	Platform() string
	Fetch(ctx context.Context, host scope.ScopedHost, cred *scope.Credential, resource string, hc *http.Client) ([]byte, error)
}

// NewAPISource construit une source API avec les clients constructeur fournis.
// insecure ne désactive la vérification TLS qu'en LABO (jamais en production).
func NewAPISource(timeout time.Duration, insecure bool, clients ...APIClient) *APISource {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	m := make(map[string]APIClient, len(clients))
	for _, c := range clients {
		m[c.Platform()] = c
	}
	return &APISource{clients: m, Timeout: timeout, insecure: insecure, now: time.Now}
}

// insecure est stocké à part (option TLS) ; httpClient() le matérialise.
func (s *APISource) httpClient() *http.Client {
	tr := &http.Transport{}
	if s.insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // labo uniquement
	}
	jar, _ := cookiejar.New(nil) // certaines API (UniFi) authentifient par cookie
	return &http.Client{Timeout: s.Timeout, Transport: tr, Jar: jar}
}

func (s *APISource) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *APISource) Collect(ctx context.Context, host scope.ScopedHost, cmd CollectCommand, cred *scope.Credential, j audit.Journal) (assess.RawEvidence, error) {
	if j == nil {
		return assess.RawEvidence{}, errors.New("scan: journal requis (collecte non journalisée interdite)")
	}
	if !cmd.IsReadOnly() {
		return assess.RawEvidence{}, fmt.Errorf("scan: commande non lecture seule refusée pour %s", cmd.ControlID)
	}
	if cred == nil {
		return assess.RawEvidence{}, errors.New("scan: credentials requis pour l'API")
	}

	ev := assess.RawEvidence{ControlID: cmd.ControlID, Host: host.Ref, Source: "api", CollectedAt: s.clock()}

	// Journalisation AVANT tout appel réseau (traçabilité non contournable).
	j.Connection(host.Ref, host.Transport, cred.Username)
	j.Command(host.Ref, cmd.ControlID, cmd.Script) // cmd.Script = ressource API demandée

	client, ok := s.clients[host.Ref.OS]
	if !ok {
		ev.CollectErr = "aucun client API pour la plateforme " + host.Ref.OS
		return ev, nil
	}
	body, err := client.Fetch(ctx, host, cred, cmd.Script, s.httpClient())
	if err != nil {
		ev.CollectErr = err.Error()
		return ev, nil
	}
	ev.Data = body
	return ev, nil
}
