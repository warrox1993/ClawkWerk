package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Zyxel (gamme ZLD : USG / USG FLEX / ZyWALL / ATP) pour PR.IR-01.1.
//
// STATUT : commandes tirées du « ZyWALL / USG (ZLD) Series CLI Reference Guide »
// officiel, NON validées sur matériel réel → d'après-doc.
//
// ATTENTION GAMME : la CLI Zyxel varie selon la lignée. Cet adaptateur cible
// ZLD (le pare-feu s'y appelle « secure policy » depuis ZLD 4.x ; sur firmwares
// plus anciens la même fonction s'appelait « firewall »). Les très anciennes
// gammes ZyNOS grand public exposent une CLI différente et bien plus pauvre :
// hors périmètre ici, on l'assume.
//
// LECTURE SEULE : `show secure-policy` « Displays all Secure Policy settings ».
// Commande d'affichage pure ; la configuration passe par le sous-mode
// `secure-policy` (action allow/deny/reject), jamais par `show`.
//
// FORMAT DE SORTIE (doc) : une règle = un bloc qui commence par
//   secure-policy rule: <n>
// puis des lignes descriptives, dont
//   from: WAN, to: ZyWALL
//   log: no, action: allow, status: yes
// On compte les blocs (RuleCount) et on détecte un refus par défaut en entrée :
// une règle venant de WAN (ou de « any ») dont l'action est deny/reject.

func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformZyNOS,
		Vendor:    "Zyxel",
		Command:   "show secure-policy",
		Normalize: zynosFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// zynosFieldAfter extrait la valeur d'un champ « clé: valeur » éventuellement
// suivi d'une virgule (ex. « from: WAN, to: ZyWALL » → from = "wan"). Renvoie ""
// si la clé n'est pas sur la ligne. Préfixe vendor pour éviter les collisions.
func zynosFieldAfter(low, key string) string {
	i := strings.Index(low, key)
	if i < 0 {
		return ""
	}
	rest := low[i+len(key):]
	rest = strings.TrimSpace(rest)
	// coupe à la première virgule (fin du champ) le cas échéant.
	if c := strings.IndexByte(rest, ','); c >= 0 {
		rest = rest[:c]
	}
	return strings.TrimSpace(rest)
}

// zynosFirewallNormalize parse la sortie de `show secure-policy`.
func zynosFirewallNormalize(raw []byte) (json.RawMessage, error) {
	ruleCount := 0
	defaultDeny := false
	curFromInbound := false // la règle courante vient-elle de WAN / any ?

	for _, l := range lines(raw) {
		low := strings.ToLower(l)

		// nouveau bloc de règle.
		if strings.HasPrefix(low, "secure-policy rule:") {
			ruleCount++
			curFromInbound = false
			continue
		}
		// zone source de la règle courante.
		if strings.HasPrefix(low, "from:") {
			from := zynosFieldAfter(low, "from:")
			curFromInbound = from == "wan" || from == "any"
			continue
		}
		// action de la règle courante ; un deny/reject sur une règle entrante
		// matérialise la politique « bloquer par défaut » en entrée.
		if strings.Contains(low, "action:") {
			act := zynosFieldAfter(low, "action:")
			if (act == "deny" || act == "reject") && curFromInbound {
				defaultDeny = true
			}
		}
	}

	return json.Marshal(NetFirewallEvidence{
		Present:            true, // équipement de sécurité : filtrage présent
		Enabled:            ruleCount > 0,
		DefaultInboundDeny: defaultDeny,
		RuleCount:          ruleCount,
		Firmware:           "", // récupérable via `show version` (adaptateur ultérieur)
	})
}
