package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func logMgmtRaw(t *testing.T, audit, forward, siem bool) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(LogMgmtEvidence{AuditEnabled: audit, LogForwarding: forward, SiemPresent: siem})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Chaque contrôle lit le(s) signal(aux) pertinent(s) : présent → Defined/Pass,
// absent → Initial/Fail. La sonde est unique, seul le sélecteur change.
func TestLogMgmt_Evaluators(t *testing.T) {
	cases := []struct {
		name    string
		eval    assess.Evaluator
		audit   bool
		forward bool
		siem    bool
		wantLvl cyfun.MaturityLevel
	}{
		{"CM0103 audit on => Defined", LogConn0103Evaluator{}, true, false, false, cyfun.Defined},
		{"CM0103 audit off => Initial", LogConn0103Evaluator{}, false, true, true, cyfun.Initial},
		{"PS0403 forward on => Defined", LogForward0403Evaluator{}, false, true, false, cyfun.Defined},
		{"PS0403 forward off => Initial", LogForward0403Evaluator{}, true, false, true, cyfun.Initial},
		{"CM0901 audit on => Defined", LogMonitor0901Evaluator{}, true, false, false, cyfun.Defined},
		{"CM0901 audit off => Initial", LogMonitor0901Evaluator{}, false, false, false, cyfun.Initial},
		{"AE0201 siem on => Defined", LogAnalysis0201Evaluator{}, false, false, true, cyfun.Defined},
		{"AE0201 siem off => Initial", LogAnalysis0201Evaluator{}, true, true, false, cyfun.Initial},
		{"AE0302 siem only => Defined", LogCorrelate0302Evaluator{}, false, false, true, cyfun.Defined},
		{"AE0302 forward only => Defined", LogCorrelate0302Evaluator{}, false, true, false, cyfun.Defined},
		{"AE0302 neither => Initial", LogCorrelate0302Evaluator{}, true, false, false, cyfun.Initial},
		{"AE0202 siem on => Defined", LogAutoAnalysis0202Evaluator{}, false, false, true, cyfun.Defined},
		{"AE0202 siem off => Initial", LogAutoAnalysis0202Evaluator{}, true, true, false, cyfun.Initial},
		{"AE0303 siem on => Defined", LogCombine0303Evaluator{}, false, false, true, cyfun.Defined},
		{"AE0303 siem off => Initial", LogCombine0303Evaluator{}, true, true, false, cyfun.Initial},
		{"PS0404 audit on => Defined", LogAuditFail0404Evaluator{}, true, false, false, cyfun.Defined},
		{"PS0404 audit off => Initial", LogAuditFail0404Evaluator{}, false, true, true, cyfun.Initial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(logMgmtRaw(t, c.audit, c.forward, c.siem))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

// Contrôles MIXTES : même signal au vert, le scan ne doit JAMAIS dépasser Defined.
func TestLogMgmt_CapsAtDefined(t *testing.T) {
	evals := []assess.Evaluator{
		LogConn0103Evaluator{}, LogForward0403Evaluator{}, LogMonitor0901Evaluator{},
		LogAnalysis0201Evaluator{}, LogCorrelate0302Evaluator{}, LogAutoAnalysis0202Evaluator{},
		LogCombine0303Evaluator{}, LogAuditFail0404Evaluator{},
	}
	for _, e := range evals {
		ha := e.Evaluate(logMgmtRaw(t, true, true, true))
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Errorf("%T a proposé %d > Defined — plafond MIXTE violé", e, ha.ProposedImplLevel)
		}
	}
}

// Une collecte échouée reste non fatale : NotAssessed, jamais une fausse faille.
func TestLogMgmt_CollectErrIsNotAssessed(t *testing.T) {
	ha := LogConn0103Evaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("collecte échouée: got %d, attendu NotAssessed", ha.ProposedImplLevel)
	}
}

// Les métadonnées portent le bon niveau et le bon flag KM.
func TestLogMgmt_Meta(t *testing.T) {
	if DECM0103Meta.Level != cyfun.LevelImportant || !DECM0103Meta.KeyMeasure {
		t.Error("DE.CM-01.3 doit être Important + Key Measure")
	}
	if PRPS0404Meta.Level != cyfun.LevelEssential || PRPS0404Meta.KeyMeasure {
		t.Error("PR.PS-04.4 doit être Essential + non-KM")
	}
	if DEAE0201Meta.Level != cyfun.LevelImportant {
		t.Error("DE.AE-02.1 doit être Important")
	}
}

func TestLogMgmt_WindowsNormalizer(t *testing.T) {
	out, err := LogMgmtWindowsNormalizer([]byte(`{"audit_enabled":true,"log_forwarding":false,"siem_present":true}`))
	if err != nil {
		t.Fatalf("normalisation Windows: %v", err)
	}
	var ev LogMgmtEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.AuditEnabled || ev.LogForwarding || !ev.SiemPresent {
		t.Errorf("preuve inattendue: %+v", ev)
	}
	// Champ requis absent => erreur.
	if _, err := LogMgmtWindowsNormalizer([]byte(`{"log_forwarding":true}`)); err == nil {
		t.Error("audit_enabled absent aurait dû échouer")
	}
	if _, err := LogMgmtWindowsNormalizer([]byte(`pas du json`)); err == nil {
		t.Error("JSON illisible aurait dû échouer")
	}
}

func TestLogMgmt_LinuxNormalizer(t *testing.T) {
	out, err := LogMgmtLinuxNormalizer([]byte("yes\nno\nyes\n"))
	if err != nil {
		t.Fatalf("normalisation Linux: %v", err)
	}
	var ev LogMgmtEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.AuditEnabled || ev.LogForwarding || !ev.SiemPresent {
		t.Errorf("preuve inattendue: %+v", ev)
	}
	// Sortie vide => erreur.
	if _, err := LogMgmtLinuxNormalizer([]byte("   \n")); err == nil {
		t.Error("sortie vide aurait dû échouer")
	}
	// Lignes manquantes => champs à false, pas d'erreur.
	out2, err := LogMgmtLinuxNormalizer([]byte("no\n"))
	if err != nil {
		t.Fatalf("une seule ligne: %v", err)
	}
	var ev2 LogMgmtEvidence
	_ = json.Unmarshal(out2, &ev2)
	if ev2.AuditEnabled || ev2.LogForwarding || ev2.SiemPresent {
		t.Errorf("lignes manquantes devraient valoir false: %+v", ev2)
	}
}
