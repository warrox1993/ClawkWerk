package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur WatchGuard Fireware pour PR.PS-04.1 (JOURNALISATION réseau).
// Fichier SÉPARÉ de l'adaptateur pare-feu.
//
// STATUT : StatusDocsUnverified — commande tirée de la « Fireware Command Line
// Interface Reference » officielle (v12.x), NON validée sur un Firebox réel.
//
// LECTURE SEULE : `show logging` « displays the log settings ». Sans argument,
// la commande affiche les réglages de journalisation de tous les composants (si
// aucun composant n'est précisé, elle montre tout). C'est une commande
// d'affichage pure ; la configuration passe par le mode `logging` / l'interface,
// jamais par `show`. Conforme à la règle de sécurité du projet.
//
// MAPPING (aligné sur l'adaptateur RouterOS de référence) :
//   - Enabled=true dès que des réglages de journalisation sont présents ;
//   - Forwarding=true si un serveur Syslog distant (adresse IP) est déclaré —
//     Fireware peut envoyer vers un WatchGuard Log Server et/ou jusqu'à trois
//     serveurs Syslog ; c'est ce renvoi distant qui matérialise la
//     centralisation recherchée ;
//   - RetentionDays=90 si Forwarding (rétention côté collecteur central assumée),
//     sinon 7 (rétention locale courte). Hypothèse documentée.
//
// Sources :
//   - Fireware Command Line Interface Reference v12.x
//     (watchguard.com/help/docs/fireware/12/en-US/CLI/)
//   - « Configure Syslog Server Settings » (help-center Fireware / logging)

func init() {
	registerNetLogging(NetAdapter{
		Platform:  PlatformFireware,
		Vendor:    "WatchGuard",
		Command:   "show logging",
		Normalize: firewareLoggingNormalize,
		Status:    StatusDocsUnverified,
	})
}

// firewareLoggingHasServerIP repère un token ressemblant à une adresse IPv4 dans
// une ligne (indice d'un serveur Syslog / Log Server distant). Préfixe
// vendor+Logging pour éviter toute collision avec les autres adaptateurs Fireware
// (firewareLooksLikeHeader, firewareFirewallNormalize…).
func firewareLoggingHasServerIP(low string) bool {
	for _, tok := range strings.Fields(low) {
		if strings.Count(tok, ".") != 3 {
			continue
		}
		onlyDigitsDots := true
		for _, r := range tok {
			if r != '.' && (r < '0' || r > '9') {
				onlyDigitsDots = false
				break
			}
		}
		if onlyDigitsDots {
			return true
		}
	}
	return false
}

// firewareLoggingNormalize parse la sortie de `show logging`.
//
// Format exact des colonnes non vérifié sur matériel (statut
// « d'après-doc-non-validé ») : on reste tolérant. Dès qu'une ligne évoque la
// journalisation (« log », « syslog »), on considère la journalisation ACTIVE ;
// dès qu'une adresse de serveur apparaît, on considère un renvoi distant
// configuré.
func firewareLoggingNormalize(raw []byte) (json.RawMessage, error) {
	enabled, forwarding := false, false
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		if strings.Contains(low, "log") || strings.Contains(low, "syslog") {
			enabled = true
		}
		if firewareLoggingHasServerIP(low) {
			enabled = true
			forwarding = true
		}
	}
	retention := 7
	if forwarding {
		retention = 90
	}
	return json.Marshal(LoggingEvidence{
		Enabled:       enabled,
		RetentionDays: retention,
		Forwarding:    forwarding,
	})
}
