package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Palo Alto PAN-OS pour PR.PS-04.1 (journalisation réseau).
//
// STATUT : d'après la documentation Palo Alto, NON validé sur matériel réel.
// La commande retenue, `show shared log-settings syslog`, reste en mode
// OPÉRATIONNEL et en LECTURE SEULE : elle affiche les profils de serveur
// syslog partagés (log-settings) tels que configurés, sans rien modifier.
//
// FORME TYPIQUE de la sortie (config imbriquée en accolades) :
//
//	syslog {
//	  Corp-Syslog {
//	    server {
//	      SIEM {
//	        transport UDP;
//	        port 514;
//	        format BSD;
//	        server 10.10.10.10;
//	        facility LOG_USER;
//	      }
//	    }
//	  }
//	}
//
// LECTURE des deux signaux :
//   - présence d'un bloc « syslog » (un profil de journalisation est défini) →
//     journalisation configurée.
//   - une ligne « server <hôte>; » (l'adresse/nom du collecteur distant, à
//     distinguer du conteneur « server { ») → renvoi vers un syslog distant.
//
// MAPPING (identique aux autres adaptateurs réseau, hypothèse documentée) :
// Forwarding=true → rétention centralisée assumée (90 j) ; sinon rétention
// locale courte (proxy 7 j). À affiner selon le collecteur réel.
func init() {
	registerNetLogging(NetAdapter{
		Platform:  PlatformPanOS,
		Vendor:    "Palo Alto",
		Command:   "show shared log-settings syslog",
		Normalize: panosLoggingNormalize,
		Status:    StatusDocsUnverified,
	})
}

// panosLoggingNormalize parse la sortie de `show shared log-settings syslog`.
func panosLoggingNormalize(raw []byte) (json.RawMessage, error) {
	enabled, forwarding := false, false

	for _, l := range lines(raw) {
		low := strings.ToLower(l)

		// Un profil syslog est déclaré : la journalisation est configurée.
		if strings.Contains(low, "syslog") {
			enabled = true
		}
		// Ligne « server <hôte>; » = collecteur distant réel. On l'isole du
		// conteneur « server { » : on exige un 2e champ qui ne soit pas « { ».
		fields := strings.Fields(low)
		if len(fields) >= 2 && fields[0] == "server" && fields[1] != "{" {
			forwarding = true
			enabled = true
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
