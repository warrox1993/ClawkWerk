package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestCapacityEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "linux"}
	cases := []struct {
		name       string
		ev         CapacityEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"sain", CapacityEvidence{DiskUsagePercent: 42}, cyfun.Defined, assess.StatusPass},
		{"sous tension (limite basse)", CapacityEvidence{DiskUsagePercent: 81}, cyfun.Defined, assess.StatusPartial},
		{"saturé", CapacityEvidence{DiskUsagePercent: 95}, cyfun.Repeatable, assess.StatusPartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := CapacityEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut: got %v want %v", ha.Findings[0].Status, c.wantStatus)
			}
		})
	}
}

func TestCapacityEvaluator_capsAtDefined(t *testing.T) {
	// Contrôle MIXTE : même un disque quasi vide ne dépasse pas Defined(3) — la
	// planification de capacité reste organisationnelle (attestée au questionnaire).
	data, _ := json.Marshal(CapacityEvidence{DiskUsagePercent: 1})
	ha := CapacityEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
	if ha.ProposedImplLevel > cyfun.Defined {
		t.Fatalf("le scan a proposé %d > Defined(3) — plafond MIXTE violé", ha.ProposedImplLevel)
	}
}

func TestCapacityEvaluator_collectErrNotAssessed(t *testing.T) {
	// Collecte échouée : jamais un score, on signale explicitement NotAssessed.
	ha := CapacityEvaluator{}.Evaluate(assess.RawEvidence{
		Host:       assess.HostRef{ID: "PC-01"},
		CollectErr: "timeout SSH",
	})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Fatalf("collecte échouée: got %d want NotAssessed(0)", ha.ProposedImplLevel)
	}
	if ha.Findings[0].Status != assess.StatusError {
		t.Errorf("statut: got %v want StatusError", ha.Findings[0].Status)
	}
}

func TestCapacityNormalizers(t *testing.T) {
	// Windows JSON.
	out, err := CapacityWindowsNormalizer([]byte(`{"disk_usage_percent":73}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev CapacityEvidence
	json.Unmarshal(out, &ev)
	if ev.DiskUsagePercent != 73 {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 1 ligne = % entier.
	out, err = CapacityLinuxNormalizer([]byte("88\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.DiskUsagePercent != 88 {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestCapacityNormalizer_rejectsGarbage(t *testing.T) {
	if _, err := CapacityWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := CapacityWindowsNormalizer([]byte(`{}`)); err == nil {
		t.Error("attendu une erreur quand disk_usage_percent est absent")
	}
	if _, err := CapacityLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
	if _, err := CapacityLinuxNormalizer([]byte("abc\n")); err == nil {
		t.Error("attendu une erreur sur taux illisible")
	}
}
