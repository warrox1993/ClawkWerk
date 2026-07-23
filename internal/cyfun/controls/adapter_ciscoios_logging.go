package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Cisco IOS / IOS-XE pour PR.PS-04.1 (journalisation réseau).
//
// STATUT : d'après la documentation Cisco, NON validé sur matériel réel.
// La commande retenue, `show logging`, est en LECTURE SEULE : elle affiche
// l'état du sous-système de journalisation (syslog) sans jamais rien modifier.
//
// FORME TYPIQUE de la sortie :
//
//	Syslog logging: enabled (0 messages dropped, ...)
//	    Console logging: level debugging, ...
//	    Buffer logging: level debugging, 67 messages logged
//	    Trap logging: level informational, 71 message lines logged
//	        Logging to 192.180.2.238 (udp port 514, ...)
//
// LECTURE des deux signaux qui nous intéressent :
//   - « Syslog logging: enabled » → le service de journalisation est actif.
//   - « Trap logging » + une (ou plusieurs) ligne(s) « Logging to <ip> » →
//     les journaux sont RENVOYÉS vers un ou plusieurs collecteurs syslog
//     distants (c'est ce que produit `logging host <ip>` / `logging trap`).
//
// MAPPING (identique à l'adaptateur RouterOS, hypothèse documentée). Sur un
// équipement réseau la rétention locale (buffer) est faible et volatile ; la
// bonne posture est le renvoi vers un collecteur central. On mappe donc :
// Forwarding=true → rétention centralisée assumée (90 j) ; sinon rétention
// locale courte (proxy 7 j). À affiner selon le collecteur réel.
func init() {
	registerNetLogging(NetAdapter{
		Platform:  PlatformCiscoIOS,
		Vendor:    "Cisco",
		Command:   "show logging",
		Normalize: ciscoiosLoggingNormalize,
		Status:    StatusDocsUnverified,
	})
}

// ciscoiosLoggingNormalize parse la sortie de `show logging`.
func ciscoiosLoggingNormalize(raw []byte) (json.RawMessage, error) {
	enabled, forwarding := false, false

	for _, l := range lines(raw) {
		low := strings.ToLower(l)

		// Ligne maîtresse : « Syslog logging: enabled » (vs « : disabled »).
		if strings.Contains(low, "syslog logging: enabled") {
			enabled = true
		}
		// Un hôte syslog distant : « Logging to <ip> » (sous « Trap logging »).
		// Sa présence atteste aussi que la journalisation est active.
		if strings.Contains(low, "logging to ") {
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
