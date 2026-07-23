package controls

import (
	"encoding/json"
	"testing"
)

func TestFortiOSSegmentationNormalizer(t *testing.T) {
	// Échantillon représentatif de `show system interface` : 2 interfaces VLAN
	// (chacune avec `set vlanid`) plus une interface physique sans vlanid. On
	// attend donc 3 segments (2 VLAN + le réseau physique natif).
	raw := []byte(`config system interface
    edit "internal"
        set vdom "root"
        set ip 192.168.1.1 255.255.255.0
        set type physical
    next
    edit "vlan10"
        set vdom "root"
        set type vlan
        set interface "internal"
        set vlanid 10
    next
    edit "vlan20"
        set vdom "root"
        set type vlan
        set interface "internal"
        set vlanid 20
    next
end`)
	out, err := fortiosSegmentationNormalize(raw)
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
	if ev.Segments != 3 {
		t.Errorf("Segments: attendu 3 (2 VLAN + natif), obtenu %d", ev.Segments)
	}
	if ev.InterSegmentFiltering {
		t.Errorf("InterSegmentFiltering: attendu false (non déductible)")
	}
}

// Aucun VLAN (que des interfaces physiques) -> 0 segment (réseau plat).
func TestFortiOSSegmentationNormalizer_NoVLAN(t *testing.T) {
	raw := []byte(`config system interface
    edit "internal"
        set type physical
    next
end`)
	out, err := fortiosSegmentationNormalize(raw)
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

func TestFortiOSSegmentationRegistered(t *testing.T) {
	found := false
	for _, a := range NetSegmentationCoverage() {
		if a.Platform == PlatformFortiOS {
			found = true
		}
	}
	if !found {
		t.Fatal("l'adaptateur segmentation FortiOS doit être enregistré")
	}
}
