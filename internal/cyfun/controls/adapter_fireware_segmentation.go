package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur WatchGuard Fireware pour PR.IR-01.2 — segmentation réseau. Fichier
// SÉPARÉ de l'adaptateur pare-feu (adapter_fireware.go).
//
// STATUT : StatusDocsUnverified — commande tirée de la « Fireware Command Line
// Interface Reference » officielle (v2026.x / v12.11), format de sortie NON
// validé sur un Firebox réel.
//
// LECTURE SEULE : `show interface` (sans argument) « displays summary
// information for all interfaces ». Commande d'affichage pure ; la configuration
// passe par le mode config, jamais par `show`.
//
// POURQUOI `show interface` ET NON `show vlan` : la référence CLI définit `show
// vlan [VLAN-name]` — elle attend le NOM d'un VLAN et affiche ce VLAN précis,
// elle n'énumère donc pas la segmentation d'un coup. `show interface` sans
// argument, lui, liste TOUTES les interfaces. Or sur Fireware chaque interface
// est rattachée à une zone de confiance (External / Trusted / Optional /
// Custom) : le nombre d'interfaces actives est donc un proxy direct du nombre de
// segments réseau. Un adaptateur = une seule commande → on choisit l'énumérateur.
//
// HONNÊTETÉ / LIMITE : faute d'un échantillon matériel du format exact des
// colonnes, on compte prudemment les lignes de contenu (ni en-tête ni
// séparateur) — d'où StatusDocsUnverified. Le filtrage inter-segments n'est pas
// déductible de cette commande → laissé à false (scan plafonné à Defined).
//
// Sources :
//   - Fireware Command Line Interface Reference v2026.1.2/v12.11.8
//     (watchguard.com/help/docs/fireware) — `show interface`, `show vlan`

func init() {
	registerNetSegmentation(NetAdapter{
		Platform:  PlatformFireware,
		Vendor:    "WatchGuard",
		Command:   "show interface",
		Normalize: firewareSegmentationNormalize,
		Status:    StatusDocsUnverified,
	})
}

// firewareSegmentationLooksLikeHeader repère les en-têtes de colonnes,
// séparateurs et lignes de synthèse que `show interface` peut intercaler, pour
// ne pas les compter comme des interfaces. Helper PROPRE à la segmentation
// (préfixe « firewareSegmentation ») : on NE réutilise PAS firewareLooksLikeHeader
// de l'adaptateur pare-feu, pour rester découplé et honorer « un fichier = un
// adaptateur autonome ».
func firewareSegmentationLooksLikeHeader(low string) bool {
	if strings.HasPrefix(low, "---") || strings.HasPrefix(low, "===") {
		return true
	}
	for _, p := range []string{"interface", "name", "number", "no.", "total", "zone", "status", "type"} {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

// firewareSegmentationNormalize compte les interfaces listées par `show
// interface` : une interface = un segment (car rattachée à une zone). Préfixe
// « firewareSegmentation » pour éviter toute collision avec l'adaptateur pare-feu.
func firewareSegmentationNormalize(raw []byte) (json.RawMessage, error) {
	segments := 0
	for _, l := range lines(raw) {
		if firewareSegmentationLooksLikeHeader(strings.ToLower(l)) {
			continue
		}
		segments++
	}
	return json.Marshal(SegmentationEvidence{
		Present:               true,
		Segments:              segments,
		InterSegmentFiltering: false, // non déductible de `show interface`
	})
}
