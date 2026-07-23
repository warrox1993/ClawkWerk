package controls

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Adaptateur Ubiquiti UniFi pour PR.IR-01.1 — via l'API du contrôleur.
//
// UniFi n'expose AUCUNE CLI de configuration pare-feu : les règles vivent dans
// le contrôleur UniFi Network et ne sont lisibles que par son API REST/JSON.
// Cet adaptateur suppose donc un transport API (scope.Transport = "api") : la
// « commande » est la RESSOURCE demandée ("firewall"), et le normaliseur parse
// le JSON renvoyé par l'endpoint /api/s/<site>/rest/firewallrule.
//
// STATUT : d'après la doc de l'API contrôleur, NON validé contre un contrôleur
// réel (endpoints/format à confirmer au banc).
func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformUniFi,
		Vendor:    "Ubiquiti",
		Command:   "firewall", // ressource API (le transport APISource la résout)
		Normalize: unifiFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// unifiFirewallRule = sous-ensemble utile d'une règle renvoyée par l'API.
type unifiFirewallRule struct {
	Ruleset string `json:"ruleset"` // ex. "WAN_IN", "LAN_IN"
	Action  string `json:"action"`  // "accept" | "drop" | "reject"
	Enabled bool   `json:"enabled"`
}

// unifiFirewallResp = enveloppe REST du contrôleur ({"data":[...]}).
type unifiFirewallResp struct {
	Data []unifiFirewallRule `json:"data"`
}

// unifiFirewallNormalize mappe la réponse JSON du contrôleur vers la preuve
// canonique. « Bloquer par défaut » = présence d'une règle drop/reject sur le
// ruleset entrant WAN_IN.
func unifiFirewallNormalize(raw []byte) (json.RawMessage, error) {
	var r unifiFirewallResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("réponse API UniFi illisible : %w", err)
	}
	count, deny := 0, false
	for _, rule := range r.Data {
		if !rule.Enabled {
			continue
		}
		count++
		act := strings.ToLower(rule.Action)
		if (strings.Contains(act, "drop") || strings.Contains(act, "reject")) &&
			strings.Contains(strings.ToUpper(rule.Ruleset), "WAN_IN") {
			deny = true
		}
	}
	return json.Marshal(NetFirewallEvidence{
		Present:            true,
		Enabled:            count > 0,
		DefaultInboundDeny: deny,
		RuleCount:          count,
	})
}
