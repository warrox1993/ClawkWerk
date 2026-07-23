package controls

import (
	"encoding/json"
	"testing"
)

// Échantillon représentatif de `show vlan brief` : VLAN 1 (défaut) + trois VLAN
// métier + les VLAN réservés 1002/1005. On attend 4 segments (1, 10, 20, 30),
// les réservés 1002-1005 étant exclus. On vérifie aussi qu'une ligne de
// continuation de ports (indentée, sans ID) n'est pas comptée.
func TestCiscoIOSSegmentationNormalizer(t *testing.T) {
	raw := []byte(`VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2
                                                Fa0/5, Fa0/6
10   VENTES                           active    Fa0/3
20   COMPTA                           active    Fa0/4
30   INVITES                          active    Fa0/7
1002 fddi-default                     act/unsup
1005 trnet-default                    act/unsup`)

	out, err := ciscoiosSegmentationNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev SegmentationEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Present {
		t.Errorf("Present: attendu true")
	}
	if ev.Segments != 4 {
		t.Errorf("Segments: attendu 4 (1,10,20,30 ; réservés 1002-1005 exclus), obtenu %d", ev.Segments)
	}
	if ev.InterSegmentFiltering {
		t.Errorf("InterSegmentFiltering: attendu false (non déductible)")
	}
}

// Switch « à plat » : seul le VLAN 1 par défaut. On attend Segments = 1, ce que
// l'évaluateur classe ensuite en « réseau plat ».
func TestCiscoIOSSegmentationNormalizer_FlatNetwork(t *testing.T) {
	raw := []byte(`VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2, Fa0/3`)

	out, err := ciscoiosSegmentationNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev SegmentationEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Segments != 1 {
		t.Errorf("Segments: attendu 1 (VLAN 1 seul), obtenu %d", ev.Segments)
	}
}
