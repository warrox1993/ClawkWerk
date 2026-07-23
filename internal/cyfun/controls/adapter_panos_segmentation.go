package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Palo Alto PAN-OS pour PR.IR-01.2 (segmentation réseau).
//
// STATUT : d'après la documentation Palo Alto, NON validé sur matériel réel.
// La commande retenue est en LECTURE SEULE : `show interface all` liste toutes
// les interfaces avec, pour les interfaces LOGIQUES, la zone de sécurité à
// laquelle chacune est rattachée. Sur PAN-OS, une zone = une frontière de
// confiance = un segment ; compter les zones DISTINCTES donne donc la mesure de
// segmentation. (On préfère cette commande opérationnelle à un `show zone` de
// mode configuration, afin de rester en mode opérationnel lecture seule.)
//
// SUBTILITÉ PAN-OS — la sortie a DEUX sections :
//   - « configured hardware interfaces » : name / id / speed-duplex-state / mac.
//   - « configured logical interfaces »  : name / id / vsys / ZONE / forwarding
//     / tag / address.
// Seule la 2e section porte la zone (4e colonne). On distingue les deux ainsi :
// sur une ligne logique, la 3e colonne (vsys) est un ENTIER, alors que sur une
// ligne matérielle la 3e colonne est « up/auto/… » (non entier). On ne retient
// donc la zone que lorsque id ET vsys sont des entiers.
//
// EXCLUSIONS : une interface logique NON rattachée à une zone décale ses
// colonnes ; la 4e colonne devient alors le « forwarding » (« vr:default »,
// « n/a »…). On écarte ces jetons (préfixe « vr: » ou valeur « n/a ») pour ne
// pas les compter comme des zones fantômes.

func init() {
	registerNetSegmentation(NetAdapter{
		Platform:  PlatformPanOS,
		Vendor:    "Palo Alto",
		Command:   "show interface all",
		Normalize: panosSegmentationNormalize,
		Status:    StatusDocsUnverified,
	})
}

// panosSegmentationNormalize parse la sortie de `show interface all`.
//
// Forme typique :
//
//	total configured hardware interfaces: 3
//	name                id  speed/duplex/state     mac address
//	ethernet1/1         16  auto/auto/up           00:1b:...
//	total configured logical interfaces: 3
//	name                id  vsys zone       forwarding   tag  address
//	ethernet1/1         16  1    L3-Trust   vr:default   0    10.0.0.1/24
//	ethernet1/2         17  1    L3-Untrust vr:default   0    198.51.100.1/24
//	ethernet1/3         18  1              vr:default    0    10.0.9.1/24
//
// On collecte les zones DISTINCTES (4e colonne des lignes logiques) ; le nombre
// de zones = le nombre de segments.
func panosSegmentationNormalize(raw []byte) (json.RawMessage, error) {
	zones := make(map[string]struct{})
	for _, l := range lines(raw) {
		fields := strings.Fields(l)
		if len(fields) < 4 {
			continue // en-têtes / lignes « total configured … »
		}
		// Ligne logique = id (col 2) et vsys (col 3) sont des entiers.
		if _, ok := atoiSafe(fields[1]); !ok {
			continue
		}
		if _, ok := atoiSafe(fields[2]); !ok {
			continue // ligne matérielle (col 3 = « up/auto/… »)
		}
		zone := fields[3]
		low := strings.ToLower(zone)
		if strings.HasPrefix(low, "vr:") || low == "n/a" {
			continue // interface sans zone : la 4e colonne est le forwarding
		}
		zones[zone] = struct{}{}
	}
	// Le filtrage inter-zones existe toujours sur PAN-OS (interzone-default =
	// deny) mais son EFFICACITÉ réelle (règles autorisées entre zones) n'est pas
	// déductible de cette seule commande → InterSegmentFiltering laissé à false ;
	// le scan plafonne à Defined, cf. commentaire du contrôle PR.IR-01.2.
	return json.Marshal(SegmentationEvidence{
		Present:               true,
		Segments:              len(zones),
		InterSegmentFiltering: false,
	})
}
