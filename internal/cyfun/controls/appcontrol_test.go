package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func appControlRaw(t *testing.T, active bool, mode string) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(AppControlEvidence{AllowlistingActive: active, Mode: mode})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Les 3 contrôles partagent la MÊME sonde AppControl avec des mappings/plafonds par
// niveau : Essential PR.PS-01.4 (SCAN pur) → Managed si actif, Initial sinon ; les
// MIXTES PR.PS-02.1 / PR.PS-05.2 plafonnent à Defined (gouvernance à attester).
func TestAppControl_Evaluators(t *testing.T) {
	cases := []struct {
		name    string
		eval    assess.Evaluator
		active  bool
		mode    string
		wantLvl cyfun.MaturityLevel
	}{
		{"PS0104 actif => Managed", AllowlistingEvaluator{}, true, "applocker", cyfun.Managed},
		{"PS0104 inactif => Initial", AllowlistingEvaluator{}, false, "none", cyfun.Initial},
		{"PS0201 actif => Defined", SoftwareRestrictionEvaluator{}, true, "wdac", cyfun.Defined},
		{"PS0201 inactif => Repeatable", SoftwareRestrictionEvaluator{}, false, "none", cyfun.Repeatable},
		{"PS0502 actif => Defined", UnauthorisedSoftwareEvaluator{}, true, "selinux", cyfun.Defined},
		{"PS0502 inactif => Repeatable", UnauthorisedSoftwareEvaluator{}, false, "none", cyfun.Repeatable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(appControlRaw(t, c.active, c.mode))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

// Le SCAN pur ne doit JAMAIS dépasser Managed(4) : le 5/5 s'atteste par override tracé.
func TestAppControl_AllowlistingCapsAtManaged(t *testing.T) {
	ha := AllowlistingEvaluator{}.Evaluate(appControlRaw(t, true, "wdac"))
	if ha.ProposedImplLevel > cyfun.Managed {
		t.Fatalf("PR.PS-01.4 a proposé %d > Managed(4) — plafond violé", ha.ProposedImplLevel)
	}
}

// Les contrôles MIXTES ne doivent JAMAIS dépasser Defined(3) par scan seul.
func TestAppControl_MixteCapsAtDefined(t *testing.T) {
	for _, e := range []assess.Evaluator{SoftwareRestrictionEvaluator{}, UnauthorisedSoftwareEvaluator{}} {
		ha := e.Evaluate(appControlRaw(t, true, "applocker"))
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("contrôle MIXTE a proposé %d > Defined(3) — plafond violé", ha.ProposedImplLevel)
		}
	}
}

// Les métadonnées portent le bon niveau et le bon flag KM (tous non-KM).
func TestAppControl_Meta(t *testing.T) {
	if PRPS0104Meta.Level != cyfun.LevelEssential || PRPS0104Meta.KeyMeasure {
		t.Error("PR.PS-01.4 doit être Essential + non-KM")
	}
	if PRPS0201Meta.Level != cyfun.LevelImportant || PRPS0201Meta.KeyMeasure {
		t.Error("PR.PS-02.1 doit être Important + non-KM")
	}
	if PRPS0502Meta.Level != cyfun.LevelImportant || PRPS0502Meta.KeyMeasure {
		t.Error("PR.PS-05.2 doit être Important + non-KM")
	}
}

// Une collecte échouée reste non fatale : NotAssessed, pas une fausse faille.
func TestAppControl_CollectErrIsNotAssessed(t *testing.T) {
	for _, e := range []assess.Evaluator{AllowlistingEvaluator{}, SoftwareRestrictionEvaluator{}, UnauthorisedSoftwareEvaluator{}} {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("collecte échouée: got %d, attendu NotAssessed", ha.ProposedImplLevel)
		}
	}
}

// Une preuve illisible (JSON corrompu) => NotAssessed également.
func TestAppControl_GarbageEvidenceIsNotAssessed(t *testing.T) {
	ha := AllowlistingEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: []byte("pas du json")})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("preuve illisible: got %d, attendu NotAssessed", ha.ProposedImplLevel)
	}
}

func TestAppControl_Normalizers(t *testing.T) {
	// Windows JSON.
	out, err := AppControlWindowsNormalizer([]byte(`{"allowlisting_active":true,"mode":"wdac"}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev AppControlEvidence
	json.Unmarshal(out, &ev)
	if !ev.AllowlistingActive || ev.Mode != "wdac" {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 2 lignes : yes/no puis moteur.
	out, err = AppControlLinuxNormalizer([]byte("yes\nselinux\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if !ev.AllowlistingActive || ev.Mode != "selinux" {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
	// Linux "no" => inactif.
	out, _ = AppControlLinuxNormalizer([]byte("no\nnone\n"))
	json.Unmarshal(out, &ev)
	if ev.AllowlistingActive {
		t.Fatalf("normalisation Linux 'no' devrait être inactive: %+v", ev)
	}
}

func TestAppControl_Normalizer_rejectsGarbage(t *testing.T) {
	if _, err := AppControlWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := AppControlWindowsNormalizer([]byte(`{"mode":"wdac"}`)); err == nil {
		t.Error("attendu une erreur quand allowlisting_active est absent")
	}
	if _, err := AppControlLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
}
