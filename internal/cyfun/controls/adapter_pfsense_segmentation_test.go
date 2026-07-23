package controls

import (
	"encoding/json"
	"testing"
)

func TestPfSenseSegmentationNormalizer(t *testing.T) {
	// Échantillon représentatif de `ifconfig -g vlan` : 3 interfaces VLAN, un nom
	// par ligne. On attend donc 4 segments (3 VLAN + le réseau natif).
	raw := []byte(`igc1.10
igc1.20
igc1.30`)
	out, err := pfsenseSegmentationNormalize(raw)
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
		t.Errorf("Segments: attendu 4 (3 VLAN + natif), obtenu %d", ev.Segments)
	}
	if ev.InterSegmentFiltering {
		t.Errorf("InterSegmentFiltering: attendu false (non déductible)")
	}
}

// Aucun VLAN configuré : sortie vide -> 0 segment (réseau plat).
func TestPfSenseSegmentationNormalizer_Empty(t *testing.T) {
	out, err := pfsenseSegmentationNormalize([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	var ev SegmentationEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Segments != 0 {
		t.Errorf("Segments: attendu 0, obtenu %d", ev.Segments)
	}
}

func TestPfSenseSegmentationRegistered(t *testing.T) {
	found := false
	for _, a := range NetSegmentationCoverage() {
		if a.Platform == PlatformPfSense {
			found = true
		}
	}
	if !found {
		t.Fatal("l'adaptateur segmentation pfSense doit être enregistré")
	}
}
