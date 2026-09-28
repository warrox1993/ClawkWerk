// Package scope modélise le périmètre d'audit — l'UNIQUE source d'hôtes du
// moteur. Il n'existe volontairement aucune fonction de découverte réseau :
// la couverture vient de l'exhaustivité de la liste fournie par le client,
// jamais d'une exploration autonome.
package scope

import (
	"time"

	"github.com/warrox1993/clawkwerk/internal/assess"
)

// Transport désigne le mode d'accès distant en lecture seule à un hôte.
type Transport string

const (
	WinRM Transport = "winrm" // Windows
	SSH   Transport = "ssh"   // Linux
	API   Transport = "api"   // équipement piloté par API (Sophos, contrôleur UniFi…)
)

// ScopedHost = un hôte à auditer, FOURNI explicitement (adresse comprise).
type ScopedHost struct {
	Ref       assess.HostRef `json:"ref"`
	Address   string         `json:"address"` // FQDN/IP fourni — jamais découvert
	Transport Transport      `json:"transport"`
	Port      int            `json:"port"`
	CredRef   string         `json:"cred_ref"` // référence logique vers un Credential
}

// AuditScope est fourni AVANT l'audit et constitue le seul point d'entrée des
// hôtes. Aucune méthode de ce paquet ne génère ou ne découvre d'hôtes.
type AuditScope struct {
	ClientRef  string       `json:"client_ref"`
	Hosts      []ScopedHost `json:"hosts"`
	ProvidedBy string       `json:"provided_by"` // qui a fourni le périmètre
	ProvidedAt time.Time    `json:"provided_at"`
}

// Credential = compte de service LECTURE SEULE fourni par le client. L'outil
// ne génère, ne devine ni ne stocke ces secrets ailleurs qu'en RAM.
//
// Le champ `secret` est NON EXPORTÉ (minuscule) : encoding/json ne sérialise
// que les champs exportés, donc le secret ne peut PAS fuir dans le JSON de
// sortie ni le rapport. Garantie portée par le langage, pas par la discipline.
type Credential struct {
	Ref      string `json:"ref"`      // "svc-audit-ro" — seul élément qui apparaît au rapport
	Username string `json:"username"` // identifiant du compte (traçabilité)
	secret   []byte // jamais sérialisé
}

// NewCredential construit un credential. Le secret est copié pour que
// l'appelant puisse effacer sa propre copie.
func NewCredential(ref, username string, secret []byte) *Credential {
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &Credential{Ref: ref, Username: username, secret: cp}
}

// Secret expose le secret pour la couche transport uniquement, au moment de la
// connexion. On ne l'expose jamais via un champ exporté.
func (c *Credential) Secret() []byte { return c.secret }

// Zero efface le secret en mémoire. À appeler en fin de session pour limiter
// la fenêtre d'exposition en RAM (contrainte stateless de la clé USB).
func (c *Credential) Zero() {
	for i := range c.secret {
		c.secret[i] = 0
	}
	c.secret = nil
}
