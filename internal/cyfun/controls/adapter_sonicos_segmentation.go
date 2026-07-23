package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur SonicWall SonicOS (SonicOS / SonicOSX 7) pour PR.IR-01.2 —
// segmentation réseau. Fichier SÉPARÉ de l'adaptateur pare-feu (adapter_sonicos.go)
// pour garder « une marque + un contrôle » isolable, comme le veut le framework.
//
// STATUT : StatusDocsUnverified — commande et format de sortie écrits d'après la
// documentation constructeur, PAS validés sur un boîtier réel.
//
// LECTURE SEULE : `show interface` (E-CLI SonicOS/X 7) affiche l'état et la
// configuration des interfaces. C'est une commande d'AFFICHAGE : elle n'écrit
// rien (la configuration passe par le mode `config` / `interface`), donc
// compatible avec un compte de service en lecture seule (cf. règle de sécurité
// du projet : aucune modification).
//
// COMMENT ON COMPTE LES SEGMENTS : sur SonicOS un VLAN se matérialise par une
// SOUS-INTERFACE nommée « <parent>:V<tag> » (ex. « X0:V100 » = VLAN 100 sous
// l'interface X0). C'est un fait documenté (SonicOS 7 System, « Configuring
// Virtual Interfaces (VLAN Subinterfaces) »). On compte donc les lignes portant
// le motif « :v » = une sous-interface VLAN, et on ajoute 1 pour le réseau natif,
// exactement comme l'adaptateur RouterOS (le patron).
//
// HONNÊTETÉ / LIMITE : cette heuristique ne « voit » que la segmentation par
// VLAN. Une segmentation portée uniquement par des zones sans VLAN serait
// sous-estimée. Le filtrage inter-segments n'est pas déductible de `show
// interface` → laissé à false (le scan plafonne à Defined, cf. prir0102.go).
//
// Sources :
//   - SonicOS/X 7 Command Line Interface Reference Guide (sonicwall.com/techdocs)
//   - SonicOS 7 System — Configuring Virtual Interfaces (VLAN Subinterfaces)
//     (nommage « X0:V100 » des sous-interfaces VLAN)

func init() {
	registerNetSegmentation(NetAdapter{
		Platform:  PlatformSonicOS,
		Vendor:    "SonicWall",
		Command:   "show interface",
		Normalize: sonicosSegmentationNormalize,
		Status:    StatusDocsUnverified,
	})
}

// sonicosSegmentationNormalize compte les sous-interfaces VLAN dans la sortie de
// `show interface` (motif « :v » du nommage « X0:V<tag> »). Segments = nb de
// VLAN + 1 (réseau natif). Préfixe « sonicosSegmentation » pour éviter toute
// collision avec l'adaptateur pare-feu SonicOS.
func sonicosSegmentationNormalize(raw []byte) (json.RawMessage, error) {
	vlans := 0
	for _, l := range lines(raw) {
		// Sous-interface VLAN SonicOS : « <parent>:V<tag> » (ex. X0:V100).
		if strings.Contains(strings.ToLower(l), ":v") {
			vlans++
		}
	}
	segments := 0
	if vlans > 0 {
		segments = vlans + 1 // + réseau natif (interface parente)
	}
	return json.Marshal(SegmentationEvidence{
		Present:               true,
		Segments:              segments,
		InterSegmentFiltering: false, // non déductible de `show interface`
	})
}
