package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

// Garantit à la COMPILATION que AntivirusEvaluator respecte le contrat
// commun — c'est le patron que suivront les 33 autres contrôles.
var _ assess.Evaluator = AntivirusEvaluator{}

// rawFrom fabrique une RawEvidence en sérialisant des faits antivirus, comme
// le ferait la couche de collecte réelle (JSON venu de WinRM/SSH).
func rawFrom(t *testing.T, host assess.HostRef, ev AntivirusEvidence) assess.RawEvidence {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return assess.RawEvidence{ControlID: "DE.CM-01.2", Host: host, Data: b}
}

func TestAntivirusEvaluator_Levels(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name       string
		ev         AntivirusEvidence
		wantLevel  cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"absent", AntivirusEvidence{Present: false},
			cyfun.Initial, assess.StatusFail},
		{"present-but-disabled", AntivirusEvidence{Present: true, Enabled: false},
			cyfun.Initial, assess.StatusFail},
		{"defs-stale", AntivirusEvidence{Present: true, Enabled: true, RealtimeProtection: true, DefinitionsAgeDays: 45},
			cyfun.Repeatable, assess.StatusPartial},
		{"realtime-off", AntivirusEvidence{Present: true, Enabled: true, RealtimeProtection: false, DefinitionsAgeDays: 2},
			cyfun.Repeatable, assess.StatusPartial},
		{"defined-defs-acceptable", AntivirusEvidence{Present: true, Enabled: true, RealtimeProtection: true, DefinitionsAgeDays: 15},
			cyfun.Defined, assess.StatusPass},
		{"managed-defs-fresh", AntivirusEvidence{Present: true, Enabled: true, RealtimeProtection: true, DefinitionsAgeDays: 2},
			cyfun.Managed, assess.StatusPass},
	}
	var e AntivirusEvaluator
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Evaluate(rawFrom(t, host, tc.ev))
			if got.ProposedImplLevel != tc.wantLevel {
				t.Errorf("niveau = %d, attendu %d", got.ProposedImplLevel, tc.wantLevel)
			}
			if len(got.Findings) != 1 {
				t.Fatalf("attendu 1 constat, obtenu %d", len(got.Findings))
			}
			if got.Findings[0].Status != tc.wantStatus {
				t.Errorf("statut = %q, attendu %q", got.Findings[0].Status, tc.wantStatus)
			}
			if got.Host.ID != host.ID {
				t.Errorf("host non propagé : %q", got.Host.ID)
			}
		})
	}
}

func TestAntivirusEvaluator_CollectError(t *testing.T) {
	var e AntivirusEvaluator
	got := e.Evaluate(assess.RawEvidence{
		ControlID: "DE.CM-01.2", Host: assess.HostRef{ID: "PC-02"},
		CollectErr: "winrm: connexion refusée",
	})
	if got.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("niveau = %d, attendu NotAssessed (0)", got.ProposedImplLevel)
	}
	if len(got.Findings) != 1 || got.Findings[0].Status != assess.StatusError {
		t.Errorf("attendu un constat en erreur, obtenu %+v", got.Findings)
	}
}

func TestAntivirusEvaluator_MalformedData(t *testing.T) {
	var e AntivirusEvaluator
	got := e.Evaluate(assess.RawEvidence{
		ControlID: "DE.CM-01.2", Host: assess.HostRef{ID: "PC-03"},
		Data: []byte("{ ceci n'est pas du json"),
	})
	if got.ProposedImplLevel != cyfun.NotAssessed {
		t.Errorf("niveau = %d, attendu NotAssessed (0)", got.ProposedImplLevel)
	}
	if len(got.Findings) != 1 || got.Findings[0].Status != assess.StatusError {
		t.Errorf("attendu un constat en erreur, obtenu %+v", got.Findings)
	}
}

// Métadonnées officielles du contrôle : DE.CM-01.2 EST un Key Measure.
func TestDECM0102Meta(t *testing.T) {
	if DECM0102Meta.ID != "DE.CM-01.2" {
		t.Errorf("ID = %q", DECM0102Meta.ID)
	}
	if !DECM0102Meta.KeyMeasure {
		t.Error("DE.CM-01.2 doit être marqué Key Measure")
	}
	if DECM0102Meta.Function != cyfun.Detect {
		t.Errorf("Function = %q, attendu DETECT", DECM0102Meta.Function)
	}
}
