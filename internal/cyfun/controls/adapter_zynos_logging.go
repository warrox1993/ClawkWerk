package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Zyxel (gamme ZLD : USG / USG FLEX / ZyWALL / ATP) pour PR.PS-04.1
// (JOURNALISATION réseau). Fichier SÉPARÉ de l'adaptateur pare-feu.
//
// STATUT : StatusDocsUnverified — commande tirée du « ZyWALL / USG (ZLD) Series
// CLI Reference Guide » officiel, NON validée sur matériel réel.
//
// ATTENTION GAMME : comme l'adaptateur pare-feu Zyxel, on cible la lignée ZLD
// (USG/FLEX/ATP), pas les vieux ZyNOS grand public. La constante de plateforme
// s'appelle historiquement PlatformZyNOS mais porte bien la gamme ZLD ici.
//
// LECTURE SEULE : `show logging status syslog` affiche l'état de la
// journalisation Syslog et la liste des serveurs Syslog distants (Remote
// Server 1~4) avec leur adresse et leur statut actif/inactif. Commande
// d'AFFICHAGE pure ; la configuration passe par le sous-mode `logging syslog`,
// jamais par `show`. Conforme à la règle de sécurité du projet.
//
// MAPPING (aligné sur l'adaptateur RouterOS de référence) :
//   - Enabled=true dès que la journalisation Syslog est active ;
//   - Forwarding=true si au moins un serveur Syslog distant (adresse IP) est
//     déclaré — la centralisation recherchée ;
//   - RetentionDays=90 si Forwarding (rétention côté collecteur central assumée),
//     sinon 7 (rétention locale courte). Hypothèse documentée.
//
// Sources :
//   - ZyWALL / USG (ZLD) Series CLI Reference Guide — chapitre « System Log » /
//     commandes `logging status syslog`
//   - Zyxel Support « How to configure syslog client option ... syslog server »

func init() {
	registerNetLogging(NetAdapter{
		Platform:  PlatformZyNOS,
		Vendor:    "Zyxel",
		Command:   "show logging status syslog",
		Normalize: zynosLoggingNormalize,
		Status:    StatusDocsUnverified,
	})
}

// zynosLoggingHasServerIP repère un token ressemblant à une adresse IPv4 dans une
// ligne (indice d'un serveur Syslog distant). Préfixe vendor+Logging pour éviter
// toute collision avec les autres adaptateurs Zyxel (zynosFieldAfter,
// zynosFirewallNormalize…).
func zynosLoggingHasServerIP(low string) bool {
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

// zynosLoggingNormalize parse la sortie de `show logging status syslog`.
//
// Format exact non vérifié sur matériel (statut « d'après-doc-non-validé ») : on
// reste tolérant. On considère la journalisation ACTIVE dès qu'une ligne signale
// un état actif (« active »/« enable ») ou mentionne Syslog ; on considère un
// renvoi distant configuré dès qu'une adresse de serveur apparaît.
func zynosLoggingNormalize(raw []byte) (json.RawMessage, error) {
	enabled, forwarding := false, false
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		if strings.Contains(low, "active") || strings.Contains(low, "enable") ||
			strings.Contains(low, "syslog") {
			enabled = true
		}
		if zynosLoggingHasServerIP(low) {
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
