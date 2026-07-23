package controls

import (
	"encoding/json"
	"testing"
)

func TestZynosSegmentationNormalizer(t *testing.T) {
	// Sortie `show interface all` simplifiée : 2 interfaces physiques + 2 VLAN
	// (vlan10, vlan20) → 2 VLAN + 1 natif = 3 segments.
	raw := []byte(`No. Name    IP Address      Status
1   ge1     203.0.113.1     up
2   ge2     192.168.1.1     up
3   vlan10  10.0.10.1       up
4   vlan20  10.0.20.1       up`)

	out, err := zynosSegmentationNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev SegmentationEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Present || ev.Segments != 3 || ev.InterSegmentFiltering {
		t.Fatalf("segmentation Zyxel inattendue: %+v", ev)
	}
}

func TestZynosSegmentationNormalizer_NoVLAN(t *testing.T) {
	// Aucune interface VLAN → réseau plat (0 segment détecté). Un en-tête
	// contenant le mot « VLAN » ne doit pas être compté (pas de chiffre après).
	raw := []byte(`No. Name    VLAN  Status
1   ge1     -     up
2   ge2     -     up`)
	out, _ := zynosSegmentationNormalize(raw)
	var ev SegmentationEvidence
	json.Unmarshal(out, &ev)
	if ev.Segments != 0 {
		t.Fatalf("attendu 0 segment sans VLAN, obtenu: %+v", ev)
	}
}

func TestZynosSegmentationRegistered_StatusDocsUnverified(t *testing.T) {
	found := false
	for _, a := range NetSegmentationCoverage() {
		if a.Platform == PlatformZyNOS {
			found = true
			if a.Vendor != "Zyxel" {
				t.Errorf("vendor attendu Zyxel, obtenu %q", a.Vendor)
			}
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur segmentation Zyxel doit être enregistré via init()")
	}
}
