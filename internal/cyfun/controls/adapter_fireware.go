package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur WatchGuard Fireware pour PR.IR-01.1 (pare-feu réseau).
//
// STATUT : commandes tirées de la « Fireware Command Line Interface Reference »
// officielle (v12.x / v2026.x), NON validées sur un Firebox réel → d'après-doc.
//
// LECTURE SEULE : sur Fireware, `show rule` « Display information about the
// policies configured for the Firebox » et, sans argument, « displays a list of
// all configured policies ». C'est une commande d'affichage pure, elle n'écrit
// rien (les modifications passent par le mode Policy et la commande `policy`).
//
// POURQUOI PAS DE DÉTECTION EXPLICITE DU « DEFAULT DENY » : l'architecture
// Fireware est un pare-feu à refus implicite — tout paquet qui ne correspond à
// AUCUNE politique est rejeté (implicit deny). Il n'existe donc pas de « règle
// finale de drop » à repérer comme sur RouterOS : le deny par défaut est une
// propriété du moteur, pas une ligne de configuration. On le porte donc à true
// par conception, en l'assumant explicitement plutôt que de le déduire d'une
// sortie qu'on ne verrait jamais. (La commande soeur `show
// default-packet-handling` documente le traitement des paquets par défaut, mais
// un adaptateur = une seule commande : on choisit celle qui donne le compte de
// règles, l'indicateur le plus discriminant pour le scoring.)

func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformFireware,
		Vendor:    "WatchGuard",
		Command:   "show rule",
		Normalize: firewareFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// firewareLooksLikeHeader repère les lignes d'en-tête / séparateurs / totaux que
// `show rule` peut intercaler autour de la liste des politiques, pour ne pas les
// compter comme des règles. Préfixe vendor pour éviter toute collision de noms.
func firewareLooksLikeHeader(low string) bool {
	if strings.HasPrefix(low, "---") || strings.HasPrefix(low, "===") {
		return true
	}
	// mots de tête de colonne ou lignes de synthèse fréquents dans les CLI.
	for _, p := range []string{"name", "policy", "number", "no.", "total", "type", "action", "enabled"} {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

// firewareFirewallNormalize parse la sortie de `show rule` : une politique par
// ligne. Faute d'un échantillon matériel vérifié du format exact des colonnes,
// on compte prudemment les lignes de contenu qui ne sont ni en-tête ni
// séparateur — d'où le statut « d'après-doc-non-validé ».
func firewareFirewallNormalize(raw []byte) (json.RawMessage, error) {
	ruleCount := 0
	for _, l := range lines(raw) {
		if firewareLooksLikeHeader(strings.ToLower(l)) {
			continue
		}
		ruleCount++
	}
	return json.Marshal(NetFirewallEvidence{
		Present:            true,          // un Firebox est un pare-feu par nature
		Enabled:            ruleCount > 0, // au moins une politique définie
		DefaultInboundDeny: true,          // refus implicite architectural (cf. en-tête)
		RuleCount:          ruleCount,
		Firmware:           "", // récupérable via `show sysinfo`/`show version` (adaptateur ultérieur)
	})
}
