package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Cisco IOS / IOS-XE pour PR.IR-01.2 (segmentation réseau).
//
// STATUT : d'après la documentation Cisco, NON validé sur matériel réel.
// La commande retenue est en LECTURE SEULE : `show vlan brief` liste tous les
// VLAN déclarés sur le switch (ID, nom, état, ports), sans jamais rien modifier.
// Sur Cisco, un VLAN = un domaine de diffusion = un segment ; compter les VLAN
// donne donc une mesure directe du cloisonnement L2.
//
// SUBTILITÉ IOS — les VLAN à EXCLURE du décompte :
//   - l'en-tête (« VLAN Name Status Ports ») et la ligne de tirets : leur
//     première colonne n'est pas un entier → naturellement écartés.
//   - les lignes de CONTINUATION de la liste de ports (un VLAN avec beaucoup de
//     ports déborde sur une 2e ligne indentée commençant par « Fa0/2, … ») :
//     leur première colonne n'est pas un entier non plus → écartées.
//   - les VLAN RÉSERVÉS 1002-1005 (fddi-default, token-ring-default,
//     fddinet-default, trnet-default) : présents par défaut sur tout IOS pour
//     des raisons historiques (FDDI / Token Ring), ils n'attestent d'AUCUNE
//     intention de segmentation → on les retire pour ne pas gonfler le score.
//
// CHOIX ASSUMÉ — on GARDE le VLAN 1 (le VLAN par défaut). Un switch « à plat »
// n'a que le VLAN 1 → Segments = 1 → l'évaluateur (evaluateSegmentation) le
// classe correctement en « réseau plat, aucune segmentation ». C'est la posture
// voulue : ne pas masquer l'absence de cloisonnement.

func init() {
	registerNetSegmentation(NetAdapter{
		Platform:  PlatformCiscoIOS,
		Vendor:    "Cisco",
		Command:   "show vlan brief",
		Normalize: ciscoiosSegmentationNormalize,
		Status:    StatusDocsUnverified,
	})
}

// ciscoiosSegmentationNormalize parse la sortie de `show vlan brief`.
//
// Forme typique :
//
//	VLAN Name                             Status    Ports
//	---- -------------------------------- --------- -------------------------------
//	1    default                          active    Fa0/1, Fa0/2
//	10   VENTES                           active    Fa0/3
//	20   COMPTA                           active    Fa0/4
//	1002 fddi-default                     act/unsup
//	1005 trnet-default                    act/unsup
//
// On compte une ligne = un VLAN dès que sa 1re colonne est un entier, en
// excluant les VLAN réservés 1002-1005 (cf. commentaire d'en-tête).
func ciscoiosSegmentationNormalize(raw []byte) (json.RawMessage, error) {
	vlans := 0
	for _, l := range lines(raw) {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		id, ok := atoiSafe(fields[0])
		if !ok {
			continue // en-tête, séparateur de tirets ou ligne de continuation
		}
		if id >= 1002 && id <= 1005 {
			continue // VLAN réservés hérités, présents par défaut → non pertinents
		}
		vlans++
	}
	// Le filtrage inter-segments (ACL entre VLAN, private-VLAN…) n'est pas
	// déductible de cette seule commande → laissé à false ; le scan plafonne à
	// Defined, cf. commentaire du contrôle PR.IR-01.2.
	return json.Marshal(SegmentationEvidence{
		Present:               true,
		Segments:              vlans,
		InterSegmentFiltering: false,
	})
}
