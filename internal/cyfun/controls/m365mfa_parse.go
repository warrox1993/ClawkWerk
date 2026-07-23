package controls

import (
	"encoding/json"
	"strings"
)

// Parseur PUR pour PR.AA-03.2 (Key Measure) : prouver l'exigence de MFA sur un
// tenant Microsoft 365 à partir de deux réponses Microsoft Graph, agrégées dans
// une seule enveloppe JSON. Aucune I/O, aucune requête réseau : la collecte est
// faite en amont, ici on ne fait qu'interpréter des octets déjà obtenus en
// LECTURE SEULE.
//
// SOURCES GRAPH (toutes deux en GET, non modifiantes) :
//
//	security_defaults  <- GET /policies/identitySecurityDefaultsEnforcementPolicy
//	conditional_access <- GET /identity/conditionalAccess/policies
//
// POURQUOI DEUX SOURCES. Microsoft 365 offre deux mécanismes exclusifs pour
// imposer la MFA. Les « Security Defaults » (un simple interrupteur global,
// typique des petites structures sans licence Entra ID P1) et l'« Accès
// conditionnel » (des politiques granulaires, réservées aux tenants licenciés).
// Un tenant conforme peut prouver sa MFA par l'un OU l'autre : on accepte donc
// les deux comme preuve suffisante.

// m365Envelope reflète la forme agrégée passée à ParseM365MFA. Tous les champs
// sont des pointeurs / slices avec omitempty : une clé absente laisse le champ
// à sa valeur nulle sans jamais provoquer d'erreur ni de panique.
type m365Envelope struct {
	SecurityDefaults  *m365SecurityDefaults `json:"security_defaults,omitempty"`
	ConditionalAccess *m365CAList           `json:"conditional_access,omitempty"`
}

// m365SecurityDefaults : le corps de la policy Security Defaults. Un seul champ
// nous intéresse, isEnabled.
type m365SecurityDefaults struct {
	IsEnabled bool `json:"isEnabled,omitempty"`
}

// m365CAList : l'enveloppe de collection Graph, qui range toujours les éléments
// sous la clé "value".
type m365CAList struct {
	Value []m365CAPolicy `json:"value,omitempty"`
}

// m365CAPolicy : une politique d'accès conditionnel, réduite aux seuls champs
// dont dépend la décision (schéma Graph réel, champs superflus ignorés).
type m365CAPolicy struct {
	State         string              `json:"state,omitempty"`
	Conditions    m365CAConditions    `json:"conditions,omitempty"`
	GrantControls m365CAGrantControls `json:"grantControls,omitempty"`
}

type m365CAConditions struct {
	Users          m365CAUsers `json:"users,omitempty"`
	ClientAppTypes []string    `json:"clientAppTypes,omitempty"`
}

type m365CAUsers struct {
	IncludeUsers []string `json:"includeUsers,omitempty"`
}

type m365CAGrantControls struct {
	Operator        string   `json:"operator,omitempty"`
	BuiltInControls []string `json:"builtInControls,omitempty"`
}

// ParseM365MFA interprète l'enveloppe agrégée et rend deux preuves distinctes :
//
//   - mfaEnforced  : le tenant impose la MFA (Security Defaults OU une politique
//     d'accès conditionnel active qui exige "mfa" pour "All").
//   - legacyBlocked : le tenant bloque l'authentification héritée (protocoles
//     legacy type Exchange ActiveSync / "other" qui contournent la MFA).
//
// Une enveloppe qui n'est pas un JSON valide renvoie err != nil. Les deux clés
// peuvent être absentes ou vides : dans ce cas les deux booléens valent false,
// sans erreur (un tenant sans aucune protection est un fait, pas une panne).
func ParseM365MFA(envelope []byte) (mfaEnforced bool, legacyBlocked bool, err error) {
	var env m365Envelope
	if err = json.Unmarshal(envelope, &env); err != nil {
		return false, false, err
	}

	// Preuve n°1 — l'interrupteur global Security Defaults suffit à lui seul.
	if env.SecurityDefaults != nil && env.SecurityDefaults.IsEnabled {
		mfaEnforced = true
	}

	if env.ConditionalAccess != nil {
		for _, p := range env.ConditionalAccess.Value {
			// Seule une politique réellement APPLIQUÉE compte. On rejette
			// explicitement "disabled" et le mode audit
			// "enabledForReportingButNotEnforced", qui n'imposent rien.
			if !strings.EqualFold(p.State, "enabled") {
				continue
			}

			// Preuve n°1 (bis) — MFA exigée pour tout le monde.
			if includesFold(p.Conditions.Users.IncludeUsers, "All") &&
				includesFold(p.GrantControls.BuiltInControls, "mfa") {
				mfaEnforced = true
			}

			// Preuve n°2 — auth héritée bloquée. Les clients legacy (ActiveSync,
			// "other") ne savent pas faire de MFA ; les laisser passer viderait
			// la MFA de son sens. Une politique qui cible ces types d'app et
			// impose "block" ferme cette porte dérobée.
			if (includesFold(p.Conditions.ClientAppTypes, "exchangeActiveSync") ||
				includesFold(p.Conditions.ClientAppTypes, "other")) &&
				includesFold(p.GrantControls.BuiltInControls, "block") {
				legacyBlocked = true
			}
		}
	}

	return mfaEnforced, legacyBlocked, nil
}

// includesFold indique si haystack contient needle, comparaison insensible à la
// casse. Graph renvoie normalement des valeurs canoniques, mais tolérer la casse
// évite un faux négatif silencieux sur une preuve de conformité.
func includesFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
