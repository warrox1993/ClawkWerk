package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur pfSense / OPNsense pour PR.PS-04.1 (journalisation réseau).
//
// STATUT : écrit d'après la documentation Netgate/OPNsense, NON validé sur
// matériel réel (voir StatusDocsUnverified). À rejouer au banc avant de s'y fier.
//
// POURQUOI `cat /conf/config.xml` : sur pfSense comme sur OPNsense, la
// configuration du renvoi syslog distant vit dans le fichier de configuration
// XML (`/conf/config.xml` ; sur pfSense `/conf` est un lien vers `/cf/conf`).
// `cat` est une commande de LECTURE PURE : elle affiche le fichier, elle
// n'écrit rien. On reste strictement dans le rôle d'audit en lecture seule.
// (Il n'existe pas de sous-commande CLI « show syslog » universelle aux deux
// distributions ; le fichier de config est la source de vérité commune.)
//
// MAPPING (identique à RouterOS, cf. adapter_routeros.go) : sur un équipement
// réseau, la rétention locale est faible ; la bonne posture est le RENVOI vers
// un collecteur central (syslog distant). On mappe donc :
//   - Enabled=true dès qu'une section <syslog> existe (journalisation configurée) ;
//   - Forwarding=true si un serveur distant est configuré ;
//   - RetentionDays = 90 si Forwarding (rétention centralisée assumée), sinon 7
//     (rétention locale courte, proxy).
// Hypothèse documentée, à affiner selon le collecteur réel.

func init() {
	registerNetLogging(NetAdapter{
		Platform:  PlatformPfSense,
		Vendor:    "pfSense/OPNsense",
		Command:   "cat /conf/config.xml", // lecture pure de la config (renvoi syslog inclus)
		Normalize: pfsenseLoggingNormalize,
		Status:    StatusDocsUnverified,
	})
}

// pfsenseLoggingNormalize parse le config.xml et détecte le renvoi syslog distant.
//
// pfSense : quand le renvoi est activé, la config contient le drapeau
// <enableremotelogging></enableremotelogging> et un ou plusieurs
// <remoteserver>IP</remoteserver> non vides. Quand il est désactivé, le drapeau
// est absent et les <remoteserver> sont des balises vides (<remoteserver></remoteserver>).
//
// OPNsense : chaque cible de renvoi est un bloc <destination ...> sous <syslog>.
//
// On ne cherche que ces marqueurs (aucun helper générique) : la présence d'un
// serveur distant suffit à conclure au renvoi centralisé.
func pfsenseLoggingNormalize(raw []byte) (json.RawMessage, error) {
	enabled, forwarding := false, false
	for _, l := range lines(raw) {
		low := strings.ToLower(strings.TrimSpace(l))
		// La section <syslog> existe → la journalisation est configurée.
		if strings.Contains(low, "<syslog") {
			enabled = true
		}
		// pfSense : drapeau explicite du renvoi distant.
		if strings.Contains(low, "enableremotelogging") {
			forwarding = true
		}
		// pfSense : un <remoteserver> NON vide (on exclut la balise vide « ></ »).
		if strings.Contains(low, "<remoteserver") && !strings.Contains(low, "></") {
			forwarding = true
		}
		// OPNsense : une destination de renvoi déclarée.
		if strings.Contains(low, "<destination") {
			forwarding = true
		}
	}
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
