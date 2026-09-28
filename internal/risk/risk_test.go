package risk

import (
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func res(id string, km bool, host string, st assess.Status) assess.ControlResult {
	return assess.ControlResult{
		Meta: cyfun.ControlMeta{ID: id, KeyMeasure: km},
		HostAssessments: []assess.HostAssessment{{
			Host:     assess.HostRef{ID: host},
			Findings: []assess.Finding{{HostID: host, Status: st, Message: "m"}},
		}},
	}
}

func TestScore_MeasuredOnly_KMWeighted(t *testing.T) {
	results := []assess.ControlResult{
		res("KM-FAIL", true, "PC1", assess.StatusFail),  // pénalise fort
		res("N-PASS", false, "PC1", assess.StatusPass),  // ne pénalise pas
		res("NA", false, "PC1", assess.StatusNA),        // exclu (non mesuré)
		res("N-PASS2", false, "PC2", assess.StatusPass), // PC2 : aucun risque
	}
	got := Score(results)
	if len(got) != 2 {
		t.Fatalf("attendu 2 hôtes, obtenu %d", len(got))
	}
	// PC1 : pénalité = 2 (KM fail) sur max = 2 (KM) + 1 (normal pass) = 3 -> 67/100.
	if got[0].HostID != "PC1" || got[0].Score != 67 {
		t.Errorf("PC1 : got %+v, attendu score 67", got[0])
	}
	if got[0].MeasuredControls != 2 { // NA exclu
		t.Errorf("PC1 : contrôles mesurés = %d, attendu 2", got[0].MeasuredControls)
	}
	if got[1].HostID != "PC2" || got[1].Score != 0 || got[1].Grade != "A" {
		t.Errorf("PC2 : got %+v, attendu score 0 note A", got[1])
	}
	if got[0].Score < got[1].Score {
		t.Error("les hôtes doivent être triés du plus risqué au moins risqué")
	}
}

func TestScore_IgnoresAttestationAndDeclarative(t *testing.T) {
	results := []assess.ControlResult{
		{Meta: cyfun.ControlMeta{ID: "DECL"}},            // déclaratif : 0 hôte
		res("SCAN-ERR", true, "PC1", assess.StatusError), // trou de collecte : exclu
	}
	got := Score(results)
	if len(got) != 0 {
		t.Errorf("aucun constat mesuré : attendu 0 hôte, obtenu %d", len(got))
	}
}
