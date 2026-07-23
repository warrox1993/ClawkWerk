package controls

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
)

// Adaptateur Sophos Firewall (XG/XGS, SFOS) pour PR.IR-01.1 — via l'API XML.
//
// La device console SFOS n'offre pas de commande read-only fiable listant les
// règles de sécurité ; la source supportée est l'API XML (port 4444) : on POST
// une requête Get<FirewallRule> et on parse le XML renvoyé. Cet adaptateur
// suppose donc un transport API (scope.Transport = "api") ; la « commande » est
// la RESSOURCE ("firewall" -> entité FirewallRule).
//
// STATUT : d'après la doc de l'API XML SFOS, NON validé contre un boîtier réel
// (schéma XML exact à confirmer au banc).
func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformSophosXG,
		Vendor:    "Sophos",
		Command:   "firewall", // ressource API (entité FirewallRule)
		Normalize: sophosxgFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// sophosFirewallRule = sous-ensemble d'une règle dans la réponse XML SFOS.
type sophosFirewallRule struct {
	Name        string   `xml:"Name"`
	Status      string   `xml:"Status"`
	Action      string   `xml:"NetworkPolicy>Action"`
	SourceZones []string `xml:"NetworkPolicy>SourceZones>Zone"`
}

// sophosFirewallResp = enveloppe <Response>…<FirewallRule>…</Response>.
type sophosFirewallResp struct {
	Rules []sophosFirewallRule `xml:"FirewallRule"`
}

// sophosxgFirewallNormalize parse le XML de l'API. « Bloquer par défaut » =
// présence d'une règle Drop/Reject dont une zone source est WAN.
func sophosxgFirewallNormalize(raw []byte) (json.RawMessage, error) {
	var r sophosFirewallResp
	if err := xml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("réponse API Sophos illisible : %w", err)
	}
	count, deny := 0, false
	for _, rule := range r.Rules {
		count++
		act := strings.ToLower(rule.Action)
		isDeny := strings.Contains(act, "drop") || strings.Contains(act, "reject") || strings.Contains(act, "deny")
		fromWAN := false
		for _, z := range rule.SourceZones {
			if strings.Contains(strings.ToUpper(z), "WAN") {
				fromWAN = true
			}
		}
		if isDeny && fromWAN {
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
