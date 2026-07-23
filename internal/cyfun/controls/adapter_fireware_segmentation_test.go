package controls

import (
	"encoding/json"
	"testing"
)

func TestFirewareSegmentationNormalizer(t *testing.T) {
	// Sortie `show interface` simplifiée : un en-tête + 3 interfaces de contenu
	// → 3 segments (chaque interface = une zone).
	raw := []byte(`Interface  Zone       Status
eth0       External   Up
eth1       Trusted    Up
eth2       Optional   Up`)

	out, err := firewareSegmentationNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev SegmentationEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Present || ev.Segments != 3 || ev.InterSegmentFiltering {
		t.Fatalf("segmentation Fireware inattendue: %+v", ev)
	}
}

func TestFirewareSegmentationNormalizer_HeadersIgnored(t *testing.T) {
	// En-têtes et séparateurs ne doivent pas être comptés comme des interfaces.
	raw := []byte(`Name       Zone
---------  ---------
eth0       External`)
	out, _ := firewareSegmentationNormalize(raw)
	var ev SegmentationEvidence
	json.Unmarshal(out, &ev)
	if ev.Segments != 1 {
		t.Fatalf("attendu 1 segment (en-têtes ignorés), obtenu: %+v", ev)
	}
}

func TestFirewareSegmentationRegistered_StatusDocsUnverified(t *testing.T) {
	found := false
	for _, a := range NetSegmentationCoverage() {
		if a.Platform == PlatformFireware {
			found = true
			if a.Vendor != "WatchGuard" {
				t.Errorf("vendor attendu WatchGuard, obtenu %q", a.Vendor)
			}
			if a.Status != StatusDocsUnverified {
				t.Errorf("statut attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
		}
	}
	if !found {
		t.Fatal("l'adaptateur segmentation Fireware doit être enregistré via init()")
	}
}
