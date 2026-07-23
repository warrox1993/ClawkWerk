package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Palo Alto PAN-OS pour PR.IR-01.1 (pare-feu réseau).
//
// STATUT : d'après la documentation Palo Alto, NON validé sur matériel réel.
// La commande retenue est en LECTURE SEULE : `show running security-policy`
// affiche l'ensemble des règles de sécurité EFFECTIVES (celles réellement
// chargées dans le dataplane), sans rien modifier.
//
// SUBTILITÉ PAN-OS — les règles « default » implicites. PAN-OS ajoute en fin
// de politique deux règles implicites, affichées par cette commande :
//   - intrazone-default  → action allow  (trafic intra-zone laissé passer)
//   - interzone-default  → action deny   (trafic inter-zones bloqué)
// C'est cette dernière qui matérialise le « bloquer par défaut » en entrée.
// On considère donc DefaultInboundDeny vrai si la DERNIÈRE action rencontrée
// appartient à la famille « deny » (deny / drop / reset-*). Si un admin a
// remplacé interzone-default par un allow (mauvaise pratique), la dernière
// action ne sera plus un deny → posture correctement signalée comme faible.

func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformPanOS,
		Vendor:    "Palo Alto",
		Command:   "show running security-policy",
		Normalize: panosFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// panosFirewallNormalize parse la sortie « bloc » de
// `show running security-policy`.
//
// Forme typique (un bloc par règle) :
//
//	"Allow Trust to DMZ; index: 1" {
//	        from L3-Trust;
//	        source any;
//	        to L3-DMZ;
//	        destination any;
//	        action allow;
//	}
//	"interzone-default; index: 2" {
//	        ...
//	        action deny;
//	}
//
// On compte une règle par ligne « action … » et on retient la dernière action.
func panosFirewallNormalize(raw []byte) (json.RawMessage, error) {
	ruleCount := 0
	lastActionDeny := false

	for _, l := range lines(raw) {
		fields := strings.Fields(strings.ToLower(l))
		// On cherche un token « action » suivi de sa valeur.
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] != "action" {
				continue
			}
			ruleCount++
			action := strings.TrimRight(fields[i+1], ";") // « allow; » → « allow »
			lastActionDeny = panosIsDenyAction(action)
			break
		}
	}

	return json.Marshal(NetFirewallEvidence{
		Present:            true, // un PAN-OS fait toujours du filtrage L3/L7
		Enabled:            ruleCount > 0,
		DefaultInboundDeny: lastActionDeny, // la dernière règle (interzone-default) bloque
		RuleCount:          ruleCount,
		Firmware:           "", // dispo via `show system info` (sw-version) — adaptateur ultérieur
	})
}

// panosIsDenyAction reconnaît la famille d'actions « bloquantes » de PAN-OS.
func panosIsDenyAction(action string) bool {
	switch action {
	case "deny", "drop", "reset-client", "reset-server", "reset-both":
		return true
	default:
		return false
	}
}
