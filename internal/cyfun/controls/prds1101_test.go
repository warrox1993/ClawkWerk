package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func TestBackupEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "SRV-01", OS: "windows"}
	cases := []struct {
		name    string
		ev      BackupEvidence
		wantLvl cyfun.MaturityLevel
	}{
		{"aucune solution", BackupEvidence{}, cyfun.Initial},
		{"solution sans planification", BackupEvidence{SolutionPresent: true}, cyfun.Repeatable},
		{"planifiée sans hors-site", BackupEvidence{SolutionPresent: true, ScheduledJob: true}, cyfun.Defined},
		{"planifiée et hors-site", BackupEvidence{SolutionPresent: true, ScheduledJob: true, OffsiteConfigured: true}, cyfun.Managed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := BackupEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

func TestBackupEvaluator_capsAtManaged(t *testing.T) {
	// Le scan ne doit JAMAIS proposer Optimizing (5) : le 5 s'atteste par preuve
	// organisationnelle (test de restauration) via override tracé.
	data, _ := json.Marshal(BackupEvidence{SolutionPresent: true, ScheduledJob: true, OffsiteConfigured: true})
	ha := BackupEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "SRV-01"}, Data: data})
	if ha.ProposedImplLevel > cyfun.Managed {
		t.Fatalf("le scan a proposé %d > Managed(4) — interdit", ha.ProposedImplLevel)
	}
}

func TestBackupNormalizers(t *testing.T) {
	// Windows JSON.
	out, err := BackupWindowsNormalizer([]byte(`{"solution_present":true,"scheduled_job":true,"offsite_configured":false}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev BackupEvidence
	json.Unmarshal(out, &ev)
	if !ev.SolutionPresent || !ev.ScheduledJob || ev.OffsiteConfigured {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 3 lignes : solution présente, planifiée, pas hors-site.
	out, err = BackupLinuxNormalizer([]byte("yes\nyes\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if !ev.SolutionPresent || !ev.ScheduledJob || ev.OffsiteConfigured {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestBackupNormalizer_rejectsGarbage(t *testing.T) {
	if _, err := BackupWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := BackupWindowsNormalizer([]byte(`{"scheduled_job":true}`)); err == nil {
		t.Error("attendu une erreur si solution_present absent")
	}
	if _, err := BackupLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
}
