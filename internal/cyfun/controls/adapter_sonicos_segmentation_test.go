package controls

import (
	"encoding/json"
	"testing"
)

func TestSonicOSSegmentationNormalizer(t *testing.T) {
	// Sortie `show interface` simplifiée : 2 interfaces physiques + 2
	// sous-interfaces VLAN (X0:V100, X0:V200) → 2 VLAN + 1 natif = 3 segments.
	raw := []byte(`X0        192.168.1.1   LAN
X1        203.0.113.1   WAN
X0:V100   10.0.100.1    LAN
X0:V200   10.0.200.1    DMZ`)

	out, err := sonicosSegmentationNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev SegmentationEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Present || ev.Segments != 3 || ev.InterSegmentFiltering {
		t.Fatalf("segmentation SonicOS inattendue: %+v", ev)
	}
}

func TestSonicOSSegmentationNormalizer_NoVLAN(t *testing.T) {
	// Aucune sous-interface VLAN → réseau plat (0 segment détecté).
	raw := []byte(`X0        192.168.1.1   LAN
X1        203.0.113.1   WAN`)
	out, _ := sonicosSegmentationNormalize(raw)
	var ev SegmentationEvidence
	json.Unmarshal(out, &ev)
	if ev.Segments != 0 {
		t.Fatalf("attendu 0 segment sans VLAN, obtenu: %+v", ev)
	}
}

func TestSonicOSSegmentationRegistered_StatusDocsUnverified(t *testing.T) {
	found := false
	for _, a := range NetSegmentationCoverage() {
		if a.Platform == PlatformSonicOS {
			found = true
			if a.Vendor != "SonicWall" {
				t.Errorf("vendor attendu SonicWall, obtenu %q", a.Vendor)
			}
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur segmentation SonicOS doit être enregistré via init()")
	}
}
