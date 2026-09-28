package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// eval invoque un évaluateur de la famille sur une preuve typée et renvoie le constat.
func evalBoot(t *testing.T, e assess.Evaluator, ev BootDeviceEvidence) assess.HostAssessment {
	t.Helper()
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01", OS: "linux"}, Data: data})
}

func TestBootIntegrityEvaluator(t *testing.T) {
	// PR.DS-01.1 sur SecureBootEnabled : true→Defined/Pass, false→Repeatable/Partial.
	ha := evalBoot(t, BootIntegrityEvaluator{}, BootDeviceEvidence{SecureBootEnabled: true})
	if ha.ProposedImplLevel != cyfun.Defined || ha.Findings[0].Status != assess.StatusPass {
		t.Errorf("Secure Boot actif: got lvl=%d status=%s want Defined/pass", ha.ProposedImplLevel, ha.Findings[0].Status)
	}
	ha = evalBoot(t, BootIntegrityEvaluator{}, BootDeviceEvidence{SecureBootEnabled: false})
	if ha.ProposedImplLevel != cyfun.Repeatable || ha.Findings[0].Status != assess.StatusPartial {
		t.Errorf("Secure Boot inactif: got lvl=%d status=%s want Repeatable/partial", ha.ProposedImplLevel, ha.Findings[0].Status)
	}
}

func TestRemovableMediaEvaluator(t *testing.T) {
	// PR.DS-01.4 sur RemovableRestricted : true→Defined/Pass, false→Repeatable/Partial.
	ha := evalBoot(t, RemovableMediaEvaluator{}, BootDeviceEvidence{RemovableRestricted: true})
	if ha.ProposedImplLevel != cyfun.Defined || ha.Findings[0].Status != assess.StatusPass {
		t.Errorf("média restreint: got lvl=%d status=%s want Defined/pass", ha.ProposedImplLevel, ha.Findings[0].Status)
	}
	ha = evalBoot(t, RemovableMediaEvaluator{}, BootDeviceEvidence{RemovableRestricted: false})
	if ha.ProposedImplLevel != cyfun.Repeatable || ha.Findings[0].Status != assess.StatusPartial {
		t.Errorf("média non restreint: got lvl=%d status=%s want Repeatable/partial", ha.ProposedImplLevel, ha.Findings[0].Status)
	}
}

func TestAutorunEvaluator(t *testing.T) {
	// PR.DS-01.5 sur AutorunDisabled : true→Defined/Pass, false→Repeatable/Fail.
	ha := evalBoot(t, AutorunEvaluator{}, BootDeviceEvidence{AutorunDisabled: true})
	if ha.ProposedImplLevel != cyfun.Defined || ha.Findings[0].Status != assess.StatusPass {
		t.Errorf("autorun désactivé: got lvl=%d status=%s want Defined/pass", ha.ProposedImplLevel, ha.Findings[0].Status)
	}
	ha = evalBoot(t, AutorunEvaluator{}, BootDeviceEvidence{AutorunDisabled: false})
	if ha.ProposedImplLevel != cyfun.Repeatable || ha.Findings[0].Status != assess.StatusFail {
		t.Errorf("autorun actif: got lvl=%d status=%s want Repeatable/fail", ha.ProposedImplLevel, ha.Findings[0].Status)
	}
}

// TestBootControls_capAtDefined : la famille est MIXTE — le scan ne doit JAMAIS proposer
// au-delà de Defined(3), même quand tous les faits sont conformes. Le 4/5 s'atteste par
// preuve organisationnelle via override tracé, jamais déduit d'un scan hôte.
func TestBootControls_capAtDefined(t *testing.T) {
	all := BootDeviceEvidence{SecureBootEnabled: true, RemovableRestricted: true, AutorunDisabled: true}
	for _, e := range []assess.Evaluator{BootIntegrityEvaluator{}, RemovableMediaEvaluator{}, AutorunEvaluator{}} {
		ha := evalBoot(t, e, all)
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Errorf("%T a proposé %d > Defined(3) — plafond MIXTE violé", e, ha.ProposedImplLevel)
		}
	}
}

// TestBootControls_collectFailed : collecte échouée → NotAssessed (jamais un score forcé).
func TestBootControls_collectFailed(t *testing.T) {
	for _, e := range []assess.Evaluator{BootIntegrityEvaluator{}, RemovableMediaEvaluator{}, AutorunEvaluator{}} {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, CollectErr: "timeout SSH"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T: collecte échouée devrait donner NotAssessed, got %d", e, ha.ProposedImplLevel)
		}
		if ha.Findings[0].Status != assess.StatusError {
			t.Errorf("%T: constat attendu StatusError, got %s", e, ha.Findings[0].Status)
		}
	}
	// Preuve illisible → NotAssessed également.
	ha := BootIntegrityEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: []byte("pas du json")})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("preuve illisible devrait donner NotAssessed, got %d", ha.ProposedImplLevel)
	}
}

func TestBootDeviceWindowsNormalizer(t *testing.T) {
	out, err := BootDeviceWindowsNormalizer([]byte(`{"secure_boot_enabled":true,"removable_restricted":false,"autorun_disabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev BootDeviceEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.SecureBootEnabled || ev.RemovableRestricted || !ev.AutorunDisabled {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
}

func TestBootDeviceWindowsNormalizer_rejects(t *testing.T) {
	if _, err := BootDeviceWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := BootDeviceWindowsNormalizer([]byte(`{"removable_restricted":true}`)); err == nil {
		t.Error("attendu une erreur quand secure_boot_enabled est absent")
	}
}

func TestBootDeviceLinuxNormalizer(t *testing.T) {
	// 3 lignes yes/no.
	out, err := BootDeviceLinuxNormalizer([]byte("yes\nno\nyes\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev BootDeviceEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.SecureBootEnabled || ev.RemovableRestricted || !ev.AutorunDisabled {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
	// Ligne manquante → false (fail-safe), pas d'erreur tant qu'au moins une ligne existe.
	out, err = BootDeviceLinuxNormalizer([]byte("no\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.SecureBootEnabled || ev.RemovableRestricted || ev.AutorunDisabled {
		t.Fatalf("lignes absentes devraient valoir false: %+v", ev)
	}
	// Entrée vide → erreur.
	if _, err := BootDeviceLinuxNormalizer([]byte("   \n")); err == nil {
		t.Error("attendu une erreur sur sortie vide")
	}
}
