package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Zyxel (gamme ZLD : USG / USG FLEX / ZyWALL / ATP) pour PR.IR-01.2 —
// segmentation réseau. Fichier SÉPARÉ de l'adaptateur pare-feu (adapter_zynos.go).
//
// STATUT : StatusDocsUnverified — commande confirmée par la doc Zyxel (CLI
// Reference ZLD + KB communauté), format de sortie NON validé sur matériel réel.
//
// LECTURE SEULE : `show interface all` liste TOUTES les interfaces de
// l'équipement (physiques ge*, VLAN vlan*, etc.). Commande d'affichage pure ;
// la création d'interface passe par le sous-mode `interface`, jamais par `show`.
//
// COMMENT ON COMPTE LES SEGMENTS : sur ZLD un VLAN est une interface nommée
// « vlan<tag> » (ex. « vlan93 »), qui apparaît dans `show interface all` et se
// détaille avec `show interface vlan93`. On compte donc les interfaces VLAN, et
// on ajoute 1 pour le réseau natif — même logique que l'adaptateur RouterOS.
//
// HONNÊTETÉ / LIMITE : l'heuristique ne « voit » que la segmentation par VLAN
// (une segmentation portée uniquement par des zones sans VLAN serait
// sous-estimée). Le filtrage inter-segments n'est pas déductible de cette
// commande → laissé à false (le scan plafonne à Defined, cf. prir0102.go).
//
// Sources :
//   - ZyWALL / USG (ZLD) Series CLI Reference Guide (`show interface all`)
//   - Zyxel Community « How to check the vlan interface status via the CLI on
//     ATP and USG Flex models » (`show interface all`, nommage « vlan93 »)

func init() {
	registerNetSegmentation(NetAdapter{
		Platform:  PlatformZyNOS,
		Vendor:    "Zyxel",
		Command:   "show interface all",
		Normalize: zynosSegmentationNormalize,
		Status:    StatusDocsUnverified,
	})
}

// zynosSegmentationNormalize compte les interfaces VLAN (« vlan<tag> ») dans la
// sortie de `show interface all`. Segments = nb de VLAN + 1 (réseau natif).
// Préfixe « zynosSegmentation » pour éviter toute collision avec l'adaptateur
// pare-feu Zyxel.
func zynosSegmentationNormalize(raw []byte) (json.RawMessage, error) {
	vlans := 0
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		// Interface VLAN ZLD : nom « vlan<tag> » (ex. vlan10, vlan93). On exige un
		// chiffre juste après « vlan » pour ne pas confondre avec un éventuel
		// en-tête de colonne « VLAN ».
		if i := strings.Index(low, "vlan"); i >= 0 {
			rest := low[i+len("vlan"):]
			if rest != "" && rest[0] >= '0' && rest[0] <= '9' {
				vlans++
			}
		}
	}
	segments := 0
	if vlans > 0 {
		segments = vlans + 1 // + réseau natif
	}
	return json.Marshal(SegmentationEvidence{
		Present:               true,
		Segments:              segments,
		InterSegmentFiltering: false, // non déductible de `show interface all`
	})
}
