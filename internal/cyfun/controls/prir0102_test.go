package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func TestNetSegmentationEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "FW-01", OS: PlatformRouterOS}
	cases := []struct {
		name    string
		ev      SegmentationEvidence
		wantLvl cyfun.MaturityLevel
	}{
		{"réseau plat", SegmentationEvidence{Present: true, Segments: 1}, cyfun.Initial},
		{"segmentation minimale", SegmentationEvidence{Present: true, Segments: 2}, cyfun.Repeatable},
		{"segments sans filtrage", SegmentationEvidence{Present: true, Segments: 4, InterSegmentFiltering: false}, cyfun.Repeatable},
		{"segmentation filtrée", SegmentationEvidence{Present: true, Segments: 4, InterSegmentFiltering: true}, cyfun.Defined},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := NetSegmentationEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

func TestRouterOSSegmentationNormalizer(t *testing.T) {
	// 3 VLAN déclarés -> 4 segments (avec le natif).
	raw := []byte(` 0 name=vlan10 vlan-id=10 interface=bridge
 1 name=vlan20 vlan-id=20 interface=bridge
 2 name=vlan30 vlan-id=30 interface=bridge`)
	out, err := routerOSSegmentationNormalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev SegmentationEvidence
	json.Unmarshal(out, &ev)
	if !ev.Present || ev.Segments != 4 {
		t.Fatalf("segmentation RouterOS inattendue: %+v", ev)
	}
}

func TestNetSegmentationCoverage_RouterOSRegistered(t *testing.T) {
	found := false
	for _, a := range NetSegmentationCoverage() {
		if a.Platform == PlatformRouterOS {
			found = true
		}
	}
	if !found {
		t.Fatal("l'adaptateur segmentation RouterOS doit être enregistré")
	}
}
