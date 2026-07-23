package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur SonicWall SonicOS (SonicOS / SonicOSX 7) pour PR.IR-01.1.
//
// STATUT : StatusDocsUnverified — commande écrite d'après la documentation
// constructeur (E-CLI SonicOS/X 7) et une KB SonicWall, mais PAS encore validée
// sur un boîtier réel.
//
// La commande `show access-rules` est LECTURE SEULE : elle liste toutes les
// règles d'accès pare-feu (une par bloc, avec leur id). La KB SonicWall confirme
// que l'E-CLI accepte des comptes « limited/readonly admin/guest », donc la
// collecte peut se faire avec un compte de service en lecture seule — cohérent
// avec la règle de sécurité du projet (aucune modification).
//
// Sources :
//   - SonicOS/X 7 Command Line Interface Reference Guide (sonicwall.com/techdocs)
//   - KB SonicWall « How to modify Firewall Access Rules using CLI »
//     (mentionne `show access-rules` et `show access-rule uuid <id>`, read-only)

func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformSonicOS,
		Vendor:    "SonicWall",
		Command:   "show access-rules",
		Normalize: sonicosFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// sonicosFirewallNormalize parse la sortie de `show access-rules`.
//
// L'E-CLI SonicOS présente chaque règle en BLOC : une ligne d'en-tête
// « access-rule ipv4 <id> » ouvre le bloc, puis des lignes indentées portent
// les champs (from <zone>, to <zone>, action <allow|deny|discard>, ...). On fait
// donc un parseur à état : on retient la zone source et l'action de la règle
// courante, et on referme le bloc à la règle suivante (ou en fin d'entrée).
//
// Détection du « bloquer par défaut » en entrée : sur SonicOS le trafic entrant
// depuis l'extérieur transite par des règles dont la zone SOURCE est WAN. On
// considère la politique « deny par défaut en entrée » satisfaite dès qu'au moins
// une règle refuse (action deny/discard/drop) du trafic dont la source est WAN —
// faute d'un « default policy » explicitement énuméré par la CLI.
func sonicosFirewallNormalize(raw []byte) (json.RawMessage, error) {
	ruleCount := 0
	defaultDeny := false

	// État de la règle en cours de lecture.
	inRule := false
	fromWAN := false
	deny := false

	// closeRule agrège la règle courante avant d'en ouvrir une nouvelle.
	closeRule := func() {
		if inRule && deny && fromWAN {
			defaultDeny = true
		}
		fromWAN = false
		deny = false
	}

	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		switch {
		case strings.HasPrefix(low, "access-rule"):
			// Nouvelle règle : on referme la précédente puis on ouvre celle-ci.
			closeRule()
			inRule = true
			ruleCount++
		case strings.HasPrefix(low, "from "):
			// « from WAN to LAN » : la première zone est la source.
			fromWAN = strings.Contains(low, "wan")
		case strings.HasPrefix(low, "action "):
			deny = strings.Contains(low, "deny") ||
				strings.Contains(low, "discard") ||
				strings.Contains(low, "drop")
		}
	}
	closeRule() // referme la dernière règle

	return json.Marshal(NetFirewallEvidence{
		Present:            true, // un SonicWall fait toujours du filtrage
		Enabled:            ruleCount > 0,
		DefaultInboundDeny: defaultDeny,
		RuleCount:          ruleCount,
		Firmware:           "", // récupérable via `show status` (adaptateur ultérieur)
	})
}
