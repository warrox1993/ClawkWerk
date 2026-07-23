package controls

import (
	"encoding/json"
	"testing"
)

// Échantillon représentatif de `show interface all` : section matérielle (à
// ignorer) + section logique avec trois interfaces. Deux zones distinctes
// (L3-Trust, L3-Untrust) ; la 3e interface n'a pas de zone (colonne décalée sur
// « vr:default ») → non comptée. On attend donc Segments = 2.
func TestPanOSSegmentationNormalizer(t *testing.T) {
	raw := []byte(`total configured hardware interfaces: 2
name                id  speed/duplex/state     mac address
ethernet1/1         16  auto/auto/up           00:1b:17:00:01:10
ethernet1/2         17  auto/auto/up           00:1b:17:00:01:11
total configured logical interfaces: 3
name                id  vsys zone       forwarding   tag  address
ethernet1/1         16  1    L3-Trust   vr:default   0    10.0.0.1/24
ethernet1/2         17  1    L3-Untrust vr:default   0    198.51.100.1/24
ethernet1/3         18  1               vr:default   0    10.0.9.1/24`)

	out, err := panosSegmentationNormalize(raw)
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
	if ev.Segments != 2 {
		t.Errorf("Segments: attendu 2 zones distinctes (L3-Trust, L3-Untrust), obtenu %d", ev.Segments)
	}
	if ev.InterSegmentFiltering {
		t.Errorf("InterSegmentFiltering: attendu false (non déductible)")
	}
}

// Deux interfaces dans la MÊME zone : une seule zone distincte → Segments = 1
// (réseau non cloisonné du point de vue des zones).
func TestPanOSSegmentationNormalizer_SingleZone(t *testing.T) {
	raw := []byte(`total configured logical interfaces: 2
name                id  vsys zone     forwarding   tag  address
ethernet1/1         16  1    L3-Trust vr:default   0    10.0.0.1/24
ethernet1/2         17  1    L3-Trust vr:default   0    10.0.1.1/24`)

	out, err := panosSegmentationNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev SegmentationEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Segments != 1 {
		t.Errorf("Segments: attendu 1 (zone unique L3-Trust), obtenu %d", ev.Segments)
	}
}
