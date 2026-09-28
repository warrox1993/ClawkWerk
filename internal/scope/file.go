package scope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/warrox1993/clawkwerk/internal/assess"
)

// fileScope = forme JSON du fichier de périmètre (-scope scope.json). Le
// périmètre est une DONNÉE fournie par le client avant l'audit, jamais une
// constante du programme : c'est ce fichier qui dit quelles machines auditer,
// par quel transport et avec quel compte de service.
//
// Exemple :
//
//	{
//	  "client": "ACME SPRL",
//	  "provided_by": "DSI client",
//	  "hosts": [
//	    {"id": "ACME-SRV01", "os": "windows", "role": "server",
//	     "address": "acme-srv01.acme.lan", "transport": "winrm", "port": 5986,
//	     "cred_ref": "svc-audit-ro"}
//	  ]
//	}
type fileScope struct {
	Client     string     `json:"client"`
	ProvidedBy string     `json:"provided_by"`
	ProvidedAt *time.Time `json:"provided_at,omitempty"` // défaut : heure de chargement
	Hosts      []fileHost `json:"hosts"`
}

type fileHost struct {
	ID        string `json:"id"`
	OS        string `json:"os"`
	Role      string `json:"role,omitempty"`
	Address   string `json:"address"`
	Transport string `json:"transport"`
	Port      int    `json:"port,omitempty"`
	CredRef   string `json:"cred_ref"`
}

// LoadFile lit et valide un fichier de périmètre. now fournit l'horodatage
// « fourni le » quand le fichier n'en porte pas.
func LoadFile(path string, now time.Time) (AuditScope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return AuditScope{}, fmt.Errorf("périmètre illisible : %w", err)
	}
	return Parse(data, now)
}

// Parse décode et valide un périmètre JSON. Les champs inconnus sont refusés :
// une faute de frappe (« adress ») doit arrêter l'audit, pas être ignorée en
// silence.
func Parse(data []byte, now time.Time) (AuditScope, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f fileScope
	if err := dec.Decode(&f); err != nil {
		return AuditScope{}, fmt.Errorf("périmètre JSON invalide : %w", err)
	}
	if strings.TrimSpace(f.Client) == "" {
		return AuditScope{}, errors.New("périmètre : champ « client » obligatoire")
	}
	if len(f.Hosts) == 0 {
		return AuditScope{}, errors.New("périmètre : au moins une machine est requise (aucune découverte réseau n'est faite)")
	}

	sc := AuditScope{
		ClientRef:  strings.TrimSpace(f.Client),
		ProvidedBy: strings.TrimSpace(f.ProvidedBy),
		ProvidedAt: now,
	}
	if f.ProvidedAt != nil {
		sc.ProvidedAt = *f.ProvidedAt
	}

	seen := make(map[string]bool, len(f.Hosts))
	for i, h := range f.Hosts {
		host, err := h.validate()
		if err != nil {
			return AuditScope{}, fmt.Errorf("périmètre, machine n°%d : %w", i+1, err)
		}
		if seen[host.Ref.ID] {
			return AuditScope{}, fmt.Errorf("périmètre : identifiant de machine en double %q", host.Ref.ID)
		}
		seen[host.Ref.ID] = true
		sc.Hosts = append(sc.Hosts, host)
	}
	return sc, nil
}

// validate contrôle une entrée et la convertit en ScopedHost.
func (h fileHost) validate() (ScopedHost, error) {
	id := strings.TrimSpace(h.ID)
	if id == "" {
		return ScopedHost{}, errors.New("champ « id » obligatoire")
	}
	// L'identifiant sert aussi de nom de fichier de preuve (<id>.<contrôle>.json) :
	// on refuse tout séparateur de chemin.
	if strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
		return ScopedHost{}, fmt.Errorf("identifiant %q invalide (séparateur de chemin interdit)", id)
	}
	osName := strings.ToLower(strings.TrimSpace(h.OS))
	if osName == "" {
		return ScopedHost{}, fmt.Errorf("%s : champ « os » obligatoire", id)
	}
	addr := strings.TrimSpace(h.Address)
	if addr == "" {
		return ScopedHost{}, fmt.Errorf("%s : champ « address » obligatoire", id)
	}
	// Une plage réseau n'est pas une machine : le périmètre liste des hôtes
	// explicites, l'outil ne balaie jamais un réseau.
	if strings.ContainsAny(addr, "/*") || strings.ContainsFunc(addr, unicode.IsSpace) {
		return ScopedHost{}, fmt.Errorf("%s : adresse %q refusée (une plage ou un motif n'est pas un hôte explicite)", id, addr)
	}
	tr := Transport(strings.ToLower(strings.TrimSpace(h.Transport)))
	switch tr {
	case SSH, WinRM, API:
	default:
		return ScopedHost{}, fmt.Errorf("%s : transport %q inconnu (attendu : ssh | winrm | api)", id, h.Transport)
	}
	if h.Port < 0 || h.Port > 65535 {
		return ScopedHost{}, fmt.Errorf("%s : port %d hors plage", id, h.Port)
	}
	cred := strings.TrimSpace(h.CredRef)
	if cred == "" {
		return ScopedHost{}, fmt.Errorf("%s : champ « cred_ref » obligatoire (compte de service fourni par le client)", id)
	}
	return ScopedHost{
		Ref:       assess.HostRef{ID: id, OS: osName, Role: strings.TrimSpace(h.Role)},
		Address:   addr,
		Transport: tr,
		Port:      h.Port,
		CredRef:   cred,
	}, nil
}

// CredRefs renvoie les références de credentials utilisées par le périmètre,
// sans doublon, dans l'ordre d'apparition.
func (s AuditScope) CredRefs() []string {
	var refs []string
	seen := map[string]bool{}
	for _, h := range s.Hosts {
		if !seen[h.CredRef] {
			seen[h.CredRef] = true
			refs = append(refs, h.CredRef)
		}
	}
	return refs
}

// accents ramène les lettres accentuées courantes (français, néerlandais,
// allemand) à leur base, pour un identifiant de session lisible.
var accents = strings.NewReplacer(
	"à", "a", "â", "a", "ä", "a", "á", "a",
	"é", "e", "è", "e", "ê", "e", "ë", "e",
	"î", "i", "ï", "i", "í", "i",
	"ô", "o", "ö", "o", "ó", "o",
	"ù", "u", "û", "u", "ü", "u", "ú", "u",
	"ç", "c", "ñ", "n", "ß", "ss",
)

// SessionID fabrique l'identifiant de session d'audit : nom du client réduit à
// [a-z0-9-] puis horodatage à la seconde, par exemple
// « acme-sprl-20260928-143005 ». Deux audits du même client ne partagent donc
// jamais le même identifiant.
func SessionID(client string, t time.Time) string {
	var b strings.Builder
	dash := false
	for _, r := range accents.Replace(strings.ToLower(client)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	slug := strings.TrimSuffix(b.String(), "-")
	if slug == "" {
		slug = "audit"
	}
	return slug + "-" + t.Format("20060102-150405")
}
