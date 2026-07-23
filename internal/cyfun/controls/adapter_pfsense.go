package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur pfSense / OPNsense pour PR.IR-01.1 (pare-feu réseau).
//
// STATUT : écrit d'après la documentation Netgate/pf, NON validé sur matériel
// réel (voir StatusDocsUnverified). À rejouer au banc avant de s'y fier.
//
// pfSense et OPNsense reposent tous deux sur `pf` (le packet filter de
// FreeBSD/OpenBSD) : la commande d'inspection est la même, d'où un seul
// adaptateur pour les deux marques.
//
// POURQUOI `pfctl -sr` : le drapeau `-s` = « show » et le sous-argument `r` =
// « rules ». C'est une commande de LECTURE PURE — elle affiche le jeu de règles
// actuellement chargé dans le noyau, elle n'écrit rien et ne recharge rien.
// (Le fichier généré /tmp/rules.debug est, lui, réécrit par le firewall à chaque
// reload : on ne le touche donc pas.) On reste ainsi strictement dans le rôle
// d'audit en lecture seule.
//
// POURQUOI ce heuristique de « deny par défaut » : contrairement à RouterOS,
// pfSense bloque par défaut tout le trafic entrant. Cette politique se
// matérialise dans le ruleset pf par une règle explicite « block ... in ... all »
// (étiquetée « Default deny rule » par pfSense). pf étant en « dernière règle
// gagnante » sauf `quick`, la présence de cette règle block entrante couvrant
// « all » est la preuve observable de la posture « bloquer par défaut ».

func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformPfSense,
		Vendor:    "pfSense/OPNsense",
		Command:   "pfctl -sr", // « show rules » : lecture seule du ruleset pf chargé
		Normalize: pfsenseFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// pfsenseFirewallNormalize parse la sortie de `pfctl -sr` : une règle pf par
// ligne (block / pass / scrub / anchor ...). On ne compte que les règles de
// FILTRAGE (block/pass) ; scrub, anchor, nat, rdr ne sont pas des règles de
// filtrage et sont ignorés pour le décompte.
func pfsenseFirewallNormalize(raw []byte) (json.RawMessage, error) {
	ruleCount := 0
	defaultDeny := false
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		isBlock := strings.HasPrefix(low, "block")
		isPass := strings.HasPrefix(low, "pass")
		if !isBlock && !isPass {
			continue // scrub / anchor / nat / en-tête : pas une règle de filtrage
		}
		ruleCount++
		// Deny entrant par défaut : une règle « block » qui s'applique en
		// entrée (" in ") sur « all » (aucune restriction de source/destination).
		// C'est la signature de la « Default deny rule » de pfSense.
		if isBlock && strings.Contains(low, " in ") && strings.Contains(low, "all") {
			defaultDeny = true
		}
	}
	return json.Marshal(NetFirewallEvidence{
		Present:            true, // pfSense/OPNsense EST un pare-feu par nature
		Enabled:            ruleCount > 0,
		DefaultInboundDeny: defaultDeny,
		RuleCount:          ruleCount,
		Firmware:           "", // dispo via `cat /etc/version` (adaptateur ultérieur)
	})
}
