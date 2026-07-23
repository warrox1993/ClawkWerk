package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestSoftwareInventoryEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "linux"}
	cases := []struct {
		name     string
		ev       SoftwareInventoryEvidence
		wantLvl  cyfun.MaturityLevel
		wantStat assess.Status
	}{
		{"énumération impossible", SoftwareInventoryEvidence{InstalledCount: 0}, cyfun.Initial, assess.StatusFail},
		{"compte négatif (illisible)", SoftwareInventoryEvidence{InstalledCount: -1}, cyfun.Initial, assess.StatusFail},
		{"énumérable", SoftwareInventoryEvidence{InstalledCount: 742}, cyfun.Defined, assess.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := SoftwareInventoryEvaluator{}.Evaluate(assess.RawEvidence{ControlID: "ID.AM-02.1", Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStat {
				t.Errorf("status: got %s want %s", ha.Findings[0].Status, c.wantStat)
			}
		})
	}
}

func TestSoftwareInventoryEvaluator_capsAtDefined(t *testing.T) {
	// Fournisseur de preuve : le scan ne peut PAS proposer mieux que Defined(3).
	// Le « documenté/revu/à jour » (Managed/Optimizing) relève de l'axe
	// Documentation, jamais d'un scan hôte.
	data, _ := json.Marshal(SoftwareInventoryEvidence{InstalledCount: 100000})
	ha := SoftwareInventoryEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
	if ha.ProposedImplLevel > cyfun.Defined {
		t.Fatalf("le scan a proposé %d > Defined(3) — interdit", ha.ProposedImplLevel)
	}
}

func TestSoftwareInventoryEvaluator_UnreadableEvidence(t *testing.T) {
	ha := SoftwareInventoryEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "X"}, Data: []byte("{pas du json")})
	if ha.ProposedImplLevel != cyfun.NotAssessed || ha.Findings[0].Status != assess.StatusError {
		t.Fatalf("preuve illisible mal gérée: %+v", ha)
	}
}

func TestSoftwareInventoryNormalizers(t *testing.T) {
	// Windows JSON {installed_count}.
	out, err := SoftwareInventoryWindowsNormalizer([]byte(`{"installed_count":312}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev SoftwareInventoryEvidence
	json.Unmarshal(out, &ev)
	if ev.InstalledCount != 312 {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux : 1 ligne = le nombre.
	out, err = SoftwareInventoryLinuxNormalizer([]byte("1876\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.InstalledCount != 1876 {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestSoftwareInventoryNormalizer_rejectsGarbage(t *testing.T) {
	if _, err := SoftwareInventoryWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := SoftwareInventoryWindowsNormalizer([]byte(`{}`)); err == nil {
		t.Error("attendu une erreur quand installed_count est absent")
	}
	if _, err := SoftwareInventoryLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
	if _, err := SoftwareInventoryLinuxNormalizer([]byte("abc\n")); err == nil {
		t.Error("attendu une erreur sur nombre illisible")
	}
}
