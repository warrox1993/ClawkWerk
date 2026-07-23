package controls

import (
	"encoding/json"
)

// Adaptateur pfSense / OPNsense pour PR.IR-01.2 (segmentation réseau).
//
// STATUT : écrit d'après la documentation Netgate/FreeBSD, NON validé sur
// matériel réel (voir StatusDocsUnverified). À rejouer au banc avant de s'y fier.
//
// POURQUOI `ifconfig -g vlan` : sur FreeBSD (donc pfSense et OPNsense), toute
// interface clonée est automatiquement rangée dans le « groupe » de sa famille ;
// les interfaces VLAN appartiennent donc au groupe nommé « vlan ». Le drapeau
// `-g <groupe>` de `ifconfig` DEMANDE la liste des interfaces d'un groupe : il
// affiche un nom d'interface VLAN par ligne (ex. `igc1.10`, `vlan20`) et rien
// d'autre. C'est une commande de LECTURE PURE — `-g` en mode requête n'écrit
// rien, ne crée ni ne modifie aucune interface. On reste strictement dans le
// rôle d'audit en lecture seule.
//
// POURQUOI ce comptage : chaque interface VLAN = un segment de niveau 2 distinct.
// Comme sur RouterOS, on ajoute 1 pour le réseau natif (non taggé) afin de
// refléter le nombre réel de domaines de diffusion. Le filtrage inter-segments
// n'est PAS déductible de cette seule commande (il faudrait lire le jeu de règles
// pf et la matrice de flux) → InterSegmentFiltering laissé à false ; le scan
// plafonne alors à Defined, conformément au commentaire du contrôle.

func init() {
	registerNetSegmentation(NetAdapter{
		Platform:  PlatformPfSense,
		Vendor:    "pfSense/OPNsense",
		Command:   "ifconfig -g vlan", // liste des interfaces du groupe « vlan » : lecture seule
		Normalize: pfsenseSegmentationNormalize,
		Status:    StatusDocsUnverified,
	})
}

// pfsenseSegmentationNormalize compte les interfaces VLAN listées par
// `ifconfig -g vlan` (un nom d'interface par ligne). `lines()` a déjà écarté les
// lignes vides, donc chaque ligne restante = une interface VLAN = un segment.
// On ajoute 1 pour le réseau natif dès qu'au moins un VLAN existe.
func pfsenseSegmentationNormalize(raw []byte) (json.RawMessage, error) {
	vlans := len(lines(raw))
	segments := 0
	if vlans > 0 {
		segments = vlans + 1 // + réseau natif (non taggé)
	}
	return json.Marshal(SegmentationEvidence{
		Present:               true, // pfSense/OPNsense sait segmenter par nature
		Segments:              segments,
		InterSegmentFiltering: false, // non déductible de cette seule commande
	})
}
