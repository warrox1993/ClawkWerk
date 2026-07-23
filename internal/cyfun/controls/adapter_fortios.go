package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Fortinet FortiOS (FortiGate) pour PR.IR-01.1 (pare-feu réseau).
//
// STATUT : écrit d'après la documentation Fortinet, NON validé sur matériel
// réel (voir StatusDocsUnverified). À rejouer au banc avant de s'y fier.
//
// POURQUOI `show firewall policy` : sur FortiOS, `show` affiche la
// configuration en cours (les commandes qui écrivent sont `config ... set ...`).
// `show firewall policy` est donc une commande de LECTURE PURE qui recrache le
// bloc `config firewall policy` avec ses `edit <id> ... next`. On reste dans le
// rôle d'audit en lecture seule.
//
// POURQUOI DefaultInboundDeny=true dès qu'il existe des policies : FortiGate
// applique un DENY IMPLICITE en fin de table de politiques (la « policy 0 ») :
// tout trafic qui ne matche aucune règle explicite est refusé. La posture
// « bloquer par défaut » en entrée est donc structurelle sur la plateforme —
// elle n'a pas besoin d'être exprimée par une règle visible. On la considère
// acquise dès qu'au moins une policy est définie (sinon l'équipement laisse tout
// passer via une éventuelle règle any-any, cas qu'on refuse de présumer bon).

func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformFortiOS,
		Vendor:    "Fortinet",
		Command:   "show firewall policy", // lecture seule de la table de policies
		Normalize: fortiosFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// fortiosFirewallNormalize parse la sortie de `show firewall policy`. La config
// FortiOS est structurée en blocs :
//
//	config firewall policy
//	    edit 1
//	        set action accept
//	    next
//	    ...
//	end
//
// Chaque `edit <id>` = une policy. On compte donc les lignes `edit ` (une par
// règle). `lines()` a déjà rogné l'indentation, d'où le HasPrefix simple.
func fortiosFirewallNormalize(raw []byte) (json.RawMessage, error) {
	ruleCount := 0
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		if strings.HasPrefix(low, "edit ") {
			ruleCount++
		}
	}
	return json.Marshal(NetFirewallEvidence{
		Present: true, // un FortiGate EST un pare-feu par nature
		Enabled: ruleCount > 0,
		// Deny implicite structurel en fin de table (policy 0) : posture
		// « bloquer par défaut » acquise dès qu'au moins une policy existe.
		DefaultInboundDeny: ruleCount > 0,
		RuleCount:          ruleCount,
		Firmware:           "", // dispo via `get system status` (adaptateur ultérieur)
	})
}
