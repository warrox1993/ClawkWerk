package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur SonicWall SonicOS (SonicOS / SonicOSX 7) pour PR.PS-04.1
// (JOURNALISATION réseau). Fichier SÉPARÉ de l'adaptateur pare-feu : un
// adaptateur = une commande = un contrôle.
//
// STATUT : StatusDocsUnverified — commande écrite d'après la documentation
// constructeur (SonicOS/X 7 Command Line Interface Reference Guide + pages
// « Device > Log > Syslog »), PAS encore validée sur un boîtier réel.
//
// LECTURE SEULE : `show log syslog` affiche la configuration de journalisation
// vers Syslog (table des serveurs Syslog, facility, format). C'est une commande
// d'AFFICHAGE pure : la configuration se fait, elle, dans le sous-mode
// `log syslog` en mode `configure` — jamais via `show`. Conforme à la règle de
// sécurité du projet (aucune modification).
//
// MAPPING (aligné sur l'adaptateur RouterOS de référence) :
//   - Enabled=true dès qu'une journalisation Syslog est configurée ;
//   - Forwarding=true si au moins un SERVEUR Syslog distant (adresse IP) est
//     déclaré — c'est la centralisation recherchée ;
//   - RetentionDays=90 si Forwarding (rétention assumée côté collecteur central),
//     sinon 7 (rétention locale courte d'un équipement réseau).
// Hypothèse documentée, à affiner selon le collecteur réel.
//
// Sources :
//   - SonicOS/X 7 Command Line Interface Reference Guide
//     (sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf)
//   - SonicOS 7.x Device Log — « Syslog Servers »
//     (sonicwall.com/.../sonicos-7.0.1-device_log/Content/Logs_Syslog/logs-syslog-servers.htm)

func init() {
	registerNetLogging(NetAdapter{
		Platform:  PlatformSonicOS,
		Vendor:    "SonicWall",
		Command:   "show log syslog",
		Normalize: sonicosLoggingNormalize,
		Status:    StatusDocsUnverified,
	})
}

// sonicosLoggingHasServerIP repère un token ressemblant à une adresse IPv4
// (quatre octets, trois points) dans une ligne : c'est le signe qu'un serveur
// Syslog distant est déclaré. Préfixe vendor+Logging pour éviter toute collision
// de noms avec les autres adaptateurs SonicOS.
func sonicosLoggingHasServerIP(low string) bool {
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

// sonicosLoggingNormalize parse la sortie de `show log syslog`.
//
// On reste volontairement tolérant sur le format exact des colonnes (statut
// « d'après-doc-non-validé ») : dès qu'une ligne évoque la journalisation Syslog,
// on considère la journalisation ACTIVE ; dès qu'une adresse de serveur apparaît,
// on considère qu'un renvoi distant (forwarding) est configuré.
func sonicosLoggingNormalize(raw []byte) (json.RawMessage, error) {
	enabled, forwarding := false, false
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		if strings.Contains(low, "syslog") || strings.Contains(low, "server") {
			enabled = true
		}
		if sonicosLoggingHasServerIP(low) {
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
