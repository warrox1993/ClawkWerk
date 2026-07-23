package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Fortinet FortiOS (FortiGate) pour PR.PS-04.1 (journalisation réseau).
//
// STATUT : écrit d'après la documentation Fortinet, NON validé sur matériel
// réel (voir StatusDocsUnverified). À rejouer au banc avant de s'y fier.
//
// POURQUOI `show log syslogd setting` : sur FortiOS, `show` affiche la
// configuration en cours (les commandes qui écrivent sont `config ... set ...`).
// `show log syslogd setting` recrache le bloc `config log syslogd setting` avec
// ses `set ...`. C'est une commande de LECTURE PURE ; on reste dans le rôle
// d'audit en lecture seule. (`get log syslogd setting` afficherait les valeurs
// effectives, y compris les défauts ; `show` suffit et reste read-only.)
//
// MAPPING (identique à RouterOS, cf. adapter_routeros.go) : sur un équipement
// réseau, la bonne posture est le RENVOI vers un collecteur central. On mappe :
//   - Enabled=true dès que le bloc de config syslogd est présent (journalisation
//     configurée) ;
//   - Forwarding=true si le renvoi distant est actif (`set status enable`) ET
//     qu'un serveur est renseigné (`set server "<hôte>"` non vide) ;
//   - RetentionDays = 90 si Forwarding (rétention centralisée assumée), sinon 7
//     (rétention locale courte, proxy).
// Hypothèse documentée, à affiner selon le collecteur réel.

func init() {
	registerNetLogging(NetAdapter{
		Platform:  PlatformFortiOS,
		Vendor:    "Fortinet",
		Command:   "show log syslogd setting", // lecture seule de la config syslog distant
		Normalize: fortiosLoggingNormalize,
		Status:    StatusDocsUnverified,
	})
}

// fortiosLoggingNormalize parse la sortie de `show log syslogd setting` :
//
//	config log syslogd setting
//	    set status enable
//	    set server "10.100.0.5"
//	    set port 514
//	end
//
// `lines()` a déjà rogné l'indentation, d'où les HasPrefix simples. On exige à la
// fois `set status enable` ET un `set server` non vide pour conclure au renvoi :
// un `set status enable` sans serveur, ou un serveur laissé à "" (défaut), ne
// constitue pas un renvoi effectif.
func fortiosLoggingNormalize(raw []byte) (json.RawMessage, error) {
	enabled, statusEnable, serverSet := false, false, false
	for _, l := range lines(raw) {
		low := strings.ToLower(strings.TrimSpace(l))
		// Présence du bloc de config syslogd → journalisation configurée.
		if strings.Contains(low, "syslogd setting") || strings.HasPrefix(low, "set status") {
			enabled = true
		}
		if strings.HasPrefix(low, "set status enable") {
			statusEnable = true
		}
		// `set server "<hôte>"` : on écarte la valeur vide `set server ""`.
		if strings.HasPrefix(low, "set server ") && !strings.Contains(low, `""`) {
			serverSet = true
		}
	}
	forwarding := statusEnable && serverSet
	retention := 7 // local, proxy
	if forwarding {
		retention = 90 // rétention centralisée assumée
	}
	return json.Marshal(LoggingEvidence{
		Enabled:       enabled,
		RetentionDays: retention,
		Forwarding:    forwarding,
	})
}
