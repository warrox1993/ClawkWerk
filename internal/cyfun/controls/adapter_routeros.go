package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur MikroTik RouterOS pour PR.IR-01.1 (pare-feu réseau).
//
// STATUT : d'après la documentation RouterOS, NON validé sur matériel réel.
// La commande est en LECTURE SEULE (`print` n'écrit rien). Sur RouterOS, la
// politique « bloquer par défaut » se matérialise par une règle de drop finale
// sur les chaînes input/forward (convention defconf) — on la détecte, faute
// d'un « default policy » explicite comme sur d'autres OS.

func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformRouterOS,
		Vendor:    "MikroTik",
		Command:   "/ip firewall filter print terse",
		Normalize: routerOSFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
	// PR.IR-01.2 — segmentation : nombre d'interfaces VLAN déclarées.
	registerNetSegmentation(NetAdapter{
		Platform:  PlatformRouterOS,
		Vendor:    "MikroTik",
		Command:   "/interface vlan print terse",
		Normalize: routerOSSegmentationNormalize,
		Status:    StatusDocsUnverified,
	})
	// PR.PS-04.1 — journalisation : actions de log, dont un éventuel envoi distant.
	registerNetLogging(NetAdapter{
		Platform:  PlatformRouterOS,
		Vendor:    "MikroTik",
		Command:   "/system logging action print terse",
		Normalize: routerOSLoggingNormalize,
		Status:    StatusDocsUnverified,
	})
}

// routerOSLoggingNormalize parse `/system logging action print` : on détecte
// qu'une action existe (journalisation active) et, surtout, qu'une action
// « remote » (syslog distant) est configurée. Sur un équipement réseau, la
// rétention locale est faible ; la bonne posture est le RENVOI vers un
// collecteur central. On mappe donc : forwarding=true → rétention centralisée
// assumée (90 j) ; sinon rétention locale courte (proxy 7 j). Hypothèse
// documentée, à affiner selon le collecteur réel.
func routerOSLoggingNormalize(raw []byte) (json.RawMessage, error) {
	enabled, forwarding := false, false
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		if strings.Contains(low, "name=") || strings.Contains(low, "target=") {
			enabled = true
		}
		if strings.Contains(low, "target=remote") || strings.Contains(low, "remote=") {
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

// routerOSSegmentationNormalize compte les interfaces VLAN (`name=...`). Chaque
// VLAN = un segment ; on ajoute 1 pour le réseau natif. Le filtrage
// inter-segments n'est pas déductible de cette seule commande → laissé à false
// (le scan plafonne à Defined, cf. commentaire du contrôle).
func routerOSSegmentationNormalize(raw []byte) (json.RawMessage, error) {
	vlans := 0
	for _, l := range lines(raw) {
		if strings.Contains(l, "name=") || strings.Contains(l, "vlan-id=") {
			vlans++
		}
	}
	segments := 0
	if vlans > 0 {
		segments = vlans + 1 // + réseau natif
	}
	return json.Marshal(SegmentationEvidence{
		Present:               true,
		Segments:              segments,
		InterSegmentFiltering: false,
	})
}

// routerOSFirewallNormalize parse la sortie « terse » de `/ip firewall filter
// print` : une règle par ligne, champs `clé=valeur`.
func routerOSFirewallNormalize(raw []byte) (json.RawMessage, error) {
	ruleCount := 0
	defaultDeny := false
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		if !strings.Contains(low, "chain=") {
			continue // en-tête / ligne parasite
		}
		ruleCount++
		drop := strings.Contains(low, "action=drop") || strings.Contains(low, "action=reject")
		onGuardChain := strings.Contains(low, "chain=input") || strings.Contains(low, "chain=forward")
		if drop && onGuardChain {
			defaultDeny = true
		}
	}
	return json.Marshal(NetFirewallEvidence{
		Present:            true, // un RouterOS embarque toujours le pare-feu
		Enabled:            ruleCount > 0,
		DefaultInboundDeny: defaultDeny,
		RuleCount:          ruleCount,
		Firmware:           "", // récupérable via `/system resource print` (adaptateur ultérieur)
	})
}
