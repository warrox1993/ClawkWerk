package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// Garantit à la COMPILATION que les deux évaluateurs respectent le contrat.
var (
	_ assess.Evaluator = VulnPlatform0802Evaluator{}
	_ assess.Evaluator = VulnAssessment0309Evaluator{}
)

func vulnScannerRaw(t *testing.T, present bool, name string) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(VulnScannerEvidence{ScannerPresent: present, ScannerName: name})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Les deux contrôles partagent la MÊME sonde de détection : scanner présent → Defined/Pass,
// absent → Initial/Fail.
func TestVulnScanner_Evaluators(t *testing.T) {
	cases := []struct {
		name       string
		eval       assess.Evaluator
		present    bool
		scanner    string
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"RA0802 présent => Defined", VulnPlatform0802Evaluator{}, true, "Nessus", cyfun.Defined, assess.StatusPass},
		{"RA0802 absent => Initial", VulnPlatform0802Evaluator{}, false, "", cyfun.Initial, assess.StatusFail},
		{"IM0309 présent => Defined", VulnAssessment0309Evaluator{}, true, "gvmd", cyfun.Defined, assess.StatusPass},
		{"IM0309 absent => Initial", VulnAssessment0309Evaluator{}, false, "", cyfun.Initial, assess.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(vulnScannerRaw(t, c.present, c.scanner))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if len(ha.Findings) != 1 || ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut inattendu: %+v", ha.Findings)
			}
		})
	}
}

// Le scan MIXTE ne doit JAMAIS dépasser Defined(3), même scanner présent : la
// dissémination/reddition de comptes et le programme de tests restent organisationnels.
func TestVulnScanner_CapsAtDefined(t *testing.T) {
	for _, e := range []assess.Evaluator{VulnPlatform0802Evaluator{}, VulnAssessment0309Evaluator{}} {
		ha := e.Evaluate(vulnScannerRaw(t, true, "Qualys"))
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("%T a proposé %d > Defined(3) — plafond violé", e, ha.ProposedImplLevel)
		}
	}
}

// Une collecte échouée reste non fatale : NotAssessed, pas une fausse faille.
func TestVulnScanner_CollectErrIsNotAssessed(t *testing.T) {
	ha := VulnPlatform0802Evaluator{}.Evaluate(assess.RawEvidence{
		Host: assess.HostRef{ID: "H1"}, CollectErr: "ssh: connexion refusée",
	})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("niveau = %d, attendu NotAssessed", ha.ProposedImplLevel)
	}
	if len(ha.Findings) != 1 || ha.Findings[0].Status != assess.StatusError {
		t.Errorf("attendu un constat en erreur, obtenu %+v", ha.Findings)
	}
}

func TestVulnScanner_Normalizers(t *testing.T) {
	// Windows JSON : scanner présent.
	out, err := VulnScannerWindowsNormalizer([]byte(`{"scanner_present":true,"scanner_name":"Nessus"}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev VulnScannerEvidence
	json.Unmarshal(out, &ev)
	if !ev.ScannerPresent || ev.ScannerName != "Nessus" {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}

	// Windows JSON : champ obligatoire absent → erreur.
	if _, err := VulnScannerWindowsNormalizer([]byte(`{"scanner_name":"x"}`)); err == nil {
		t.Error("attendu une erreur quand scanner_present est absent")
	}

	// Linux : deux lignes yes + nom.
	out, err = VulnScannerLinuxNormalizer([]byte("yes\ngvmd\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if !ev.ScannerPresent || ev.ScannerName != "gvmd" {
		t.Fatalf("normalisation Linux (yes) inattendue: %+v", ev)
	}

	// Linux : « no » seul est valide (scanner absent).
	out, err = VulnScannerLinuxNormalizer([]byte("no\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.ScannerPresent {
		t.Fatalf("normalisation Linux (no) inattendue: %+v", ev)
	}
}

func TestVulnScanner_Normalizer_rejectsEmpty(t *testing.T) {
	if _, err := VulnScannerLinuxNormalizer([]byte("   \n")); err == nil {
		t.Error("attendu une erreur sur entrée vide (0 ligne)")
	}
	if _, err := VulnScannerWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur JSON invalide")
	}
}

// Métadonnées : Essential, non Key Measure, bon niveau et bonne fonction.
func TestVulnScanner_Meta(t *testing.T) {
	if IDRA0802Meta.ID != "ID.RA-08.2" || IDRA0802Meta.Level != cyfun.LevelEssential || IDRA0802Meta.KeyMeasure {
		t.Errorf("ID.RA-08.2 doit être Essential + non-KM: %+v", IDRA0802Meta)
	}
	if IDIM0309Meta.ID != "ID.IM-03.9" || IDIM0309Meta.Level != cyfun.LevelEssential || IDIM0309Meta.KeyMeasure {
		t.Errorf("ID.IM-03.9 doit être Essential + non-KM: %+v", IDIM0309Meta)
	}
	if IDRA0802Meta.Function != cyfun.Identify || IDIM0309Meta.Function != cyfun.Identify {
		t.Error("les deux contrôles relèvent de la fonction IDENTIFY")
	}
}
