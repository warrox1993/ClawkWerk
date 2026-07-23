package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Fortinet FortiOS (FortiGate) pour PR.IR-01.2 (segmentation réseau).
//
// STATUT : écrit d'après la documentation Fortinet, NON validé sur matériel
// réel (voir StatusDocsUnverified). À rejouer au banc avant de s'y fier.
//
// POURQUOI `show system interface` : sur FortiOS, `show` affiche la configuration
// en cours (les commandes qui écrivent sont `config ... set ...`). `show system
// interface` recrache donc, en LECTURE PURE, le bloc `config system interface`
// avec un sous-bloc `edit "<nom>" ... next` par interface logique. On reste dans
// le rôle d'audit en lecture seule.
//
// POURQUOI compter `set vlanid` : sur FortiGate, un segment de niveau 2 se
// matérialise par une interface VLAN, c.-à-d. un `edit` portant `set type vlan`
// et surtout `set vlanid <n>`. Seules les interfaces VLAN possèdent un `vlanid` :
// compter ces lignes donne sans ambiguïté le nombre de VLAN, indépendamment de
// l'indentation (déjà rognée par `lines()`). On ajoute 1 pour le réseau physique
// natif, comme sur les autres plateformes.
//
// NB : FortiOS expose aussi des « zones » (regroupements d'interfaces par
// frontière de confiance) via `show system zone`. C'est un second angle de
// segmentation, mais un adaptateur ne porte qu'UNE commande : on retient ici le
// décompte des VLAN, primitive de segmentation la plus universellement présente.
//
// Le filtrage inter-segments n'est PAS déductible de cette seule commande (il
// faudrait lire `show firewall policy` et la matrice de flux) →
// InterSegmentFiltering laissé à false ; le scan plafonne alors à Defined,
// conformément au commentaire du contrôle.

func init() {
	registerNetSegmentation(NetAdapter{
		Platform:  PlatformFortiOS,
		Vendor:    "Fortinet",
		Command:   "show system interface", // lecture seule des interfaces (dont VLAN)
		Normalize: fortiosSegmentationNormalize,
		Status:    StatusDocsUnverified,
	})
}

// fortiosSegmentationNormalize compte les sous-interfaces VLAN dans la sortie de
// `show system interface` : une ligne `set vlanid <n>` par VLAN. On ajoute 1 pour
// le réseau physique natif dès qu'au moins un VLAN existe.
func fortiosSegmentationNormalize(raw []byte) (json.RawMessage, error) {
	vlans := 0
	for _, l := range lines(raw) {
		if strings.HasPrefix(strings.ToLower(l), "set vlanid ") {
			vlans++
		}
	}
	segments := 0
	if vlans > 0 {
		segments = vlans + 1 // + réseau physique natif
	}
	return json.Marshal(SegmentationEvidence{
		Present:               true, // un FortiGate sait segmenter par nature
		Segments:              segments,
		InterSegmentFiltering: false, // non déductible de cette seule commande
	})
}
