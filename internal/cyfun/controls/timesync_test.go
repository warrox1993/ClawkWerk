package controls

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func TestTimeSyncEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "linux"}
	cases := []struct {
		name    string
		ev      TimeSyncEvidence
		wantLvl cyfun.MaturityLevel
		wantSt  assess.Status
	}{
		{"synchronisé", TimeSyncEvidence{Synchronized: true, Source: "ntp.belnet.be"}, cyfun.Managed, assess.StatusPass},
		{"non synchronisé", TimeSyncEvidence{Synchronized: false}, cyfun.Repeatable, assess.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := TimeSyncEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantSt {
				t.Errorf("statut: got %q want %q", ha.Findings[0].Status, c.wantSt)
			}
		})
	}
}

func TestTimeSyncEvaluator_mentionneLaSource(t *testing.T) {
	data, _ := json.Marshal(TimeSyncEvidence{Synchronized: true, Source: "ntp.belnet.be"})
	ha := TimeSyncEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
	if !strings.Contains(ha.Findings[0].Message, "ntp.belnet.be") {
		t.Errorf("le message doit citer la source : %q", ha.Findings[0].Message)
	}
}

func TestTimeSyncEvaluator_capsAtManaged(t *testing.T) {
	// Le scan ne doit JAMAIS proposer Optimizing (5) : le 5 s'atteste par preuve
	// organisationnelle via override tracé, jamais déduit d'un scan hôte.
	data, _ := json.Marshal(TimeSyncEvidence{Synchronized: true, Source: "ntp.belnet.be"})
	ha := TimeSyncEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
	if ha.ProposedImplLevel > cyfun.Managed {
		t.Fatalf("le scan a proposé %d > Managed(4) — interdit", ha.ProposedImplLevel)
	}
}

func TestTimeSyncEvaluator_collecteEchoueeNonAssessed(t *testing.T) {
	ha := TimeSyncEvaluator{}.Evaluate(assess.RawEvidence{
		Host:       assess.HostRef{ID: "PC-01"},
		CollectErr: "timeout SSH",
	})
	if ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Fatalf("collecte échouée doit donner NotAssessed, got %d", ha.ProposedImplLevel)
	}
	if ha.Findings[0].Status != assess.StatusError {
		t.Errorf("statut attendu error, got %q", ha.Findings[0].Status)
	}
}

func TestTimeSyncNormalizers(t *testing.T) {
	// Windows JSON.
	// Source EXTERNE (nom pointé) -> synchronisé (déduit en Go, neutre en langue).
	out, err := TimeSyncWindowsNormalizer([]byte(`{"source":"time.windows.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev TimeSyncEvidence
	json.Unmarshal(out, &ev)
	if !ev.Synchronized || ev.Source != "time.windows.com" {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Horloge LOCALE (libellé traduit, sans point) -> NON synchronisé, sans erreur.
	out, _ = TimeSyncWindowsNormalizer([]byte(`{"source":"Horloge CMOS locale"}`))
	var evLocal TimeSyncEvidence
	json.Unmarshal(out, &evLocal)
	if evLocal.Synchronized {
		t.Errorf("horloge locale ne doit pas être « synchronisée » : %+v", evLocal)
	}

	// Linux 2 lignes : yes/no puis source.
	out, err = TimeSyncLinuxNormalizer([]byte("yes\nntp.belnet.be\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if !ev.Synchronized || ev.Source != "ntp.belnet.be" {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}

	// Linux non synchronisé, source inconnue → Source vide. Variable FRAÎCHE :
	// Source a le tag omitempty, donc un JSON sans source ne réinitialise pas un
	// ev réutilisé (piège de test, pas un bug du normaliseur).
	out, err = TimeSyncLinuxNormalizer([]byte("no\nunknown\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev2 TimeSyncEvidence
	json.Unmarshal(out, &ev2)
	if ev2.Synchronized || ev2.Source != "" {
		t.Fatalf("normalisation Linux (non sync) inattendue: %+v", ev2)
	}
}

func TestTimeSyncNormalizer_rejectsGarbage(t *testing.T) {
	if _, err := TimeSyncWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := TimeSyncWindowsNormalizer([]byte(`{}`)); err == nil {
		t.Error("attendu une erreur quand le champ source est absent")
	}
	if _, err := TimeSyncLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
}
