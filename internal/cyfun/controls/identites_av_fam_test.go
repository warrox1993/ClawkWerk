package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func accessReviewRaw(t *testing.T, inactive, total int) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(AccessReviewEvidence{InactiveAccounts: inactive, TotalLocalAccounts: total})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

func remoteMFARaw(t *testing.T, enabled, hardened bool) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(RemoteMFAEvidence{RemoteAccessEnabled: enabled, Hardened: hardened})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// --- PR.AA-01.3 : comptes dormants (réutilise AccessReview) ---
func TestDormant0103_Evaluator(t *testing.T) {
	cases := []struct {
		name       string
		inactive   int
		total      int
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"énumération impossible", 0, 0, cyfun.Initial, assess.StatusFail},
		{"beaucoup de dormants", 7, 20, cyfun.Repeatable, assess.StatusPartial},
		{"quelques dormants", 2, 20, cyfun.Defined, assess.StatusPartial},
		{"aucun dormant", 0, 20, cyfun.Defined, assess.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := Dormant0103Evaluator{}.Evaluate(accessReviewRaw(t, c.inactive, c.total))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut: got %q want %q", ha.Findings[0].Status, c.wantStatus)
			}
		})
	}
}

// --- PR.AA-02.2 : comptes uniques (réutilise AccessReview) ---
func TestUniqueAccounts0202_Evaluator(t *testing.T) {
	cases := []struct {
		name       string
		total      int
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"énumération OK => Defined/Partial", 12, cyfun.Defined, assess.StatusPartial},
		{"énumération impossible => Initial/Fail", 0, cyfun.Initial, assess.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := UniqueAccounts0202Evaluator{}.Evaluate(accessReviewRaw(t, 0, c.total))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut: got %q want %q", ha.Findings[0].Status, c.wantStatus)
			}
		})
	}
}

// --- PR.AA-01.4 : MFA/certificats (réutilise RemoteMFA) ---
func TestAuthFactor0104_Evaluator(t *testing.T) {
	cases := []struct {
		name       string
		enabled    bool
		hardened   bool
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"pas d'accès distant => Defined/Pass", false, false, cyfun.Defined, assess.StatusPass},
		{"durci => Defined/Partial", true, true, cyfun.Defined, assess.StatusPartial},
		{"exposé non durci => Repeatable/Fail", true, false, cyfun.Repeatable, assess.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := AuthFactor0104Evaluator{}.Evaluate(remoteMFARaw(t, c.enabled, c.hardened))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut: got %q want %q", ha.Findings[0].Status, c.wantStatus)
			}
		})
	}
}

// Preuve PARTIELLE : aucun des trois évaluateurs ne doit dépasser Defined (3),
// même dans le cas le plus favorable (aucun dormant / durci / pas d'exposition).
func TestIdentitesAV_CapAtDefined(t *testing.T) {
	maxes := []assess.HostAssessment{
		Dormant0103Evaluator{}.Evaluate(accessReviewRaw(t, 0, 50)),
		UniqueAccounts0202Evaluator{}.Evaluate(accessReviewRaw(t, 0, 50)),
		AuthFactor0104Evaluator{}.Evaluate(remoteMFARaw(t, false, false)),
	}
	for i, ha := range maxes {
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Errorf("évaluateur %d : plafond dépassé, got %d > Defined (%d)", i, ha.ProposedImplLevel, cyfun.Defined)
		}
	}
}

// Les métadonnées portent le bon niveau (Essential) et le bon flag KM (non-KM).
func TestIdentitesAV_Meta(t *testing.T) {
	for _, m := range []cyfun.ControlMeta{PRAA0103Meta, PRAA0202Meta, PRAA0104Meta} {
		if m.Level != cyfun.LevelEssential || m.KeyMeasure {
			t.Errorf("%s doit être Essential + non-KM (got Level=%q KM=%v)", m.ID, m.Level, m.KeyMeasure)
		}
	}
}

// Collecte échouée : NotAssessed pour chaque évaluateur, jamais une fausse faille.
func TestIdentitesAV_CollectErrIsNotAssessed(t *testing.T) {
	evals := []assess.Evaluator{Dormant0103Evaluator{}, UniqueAccounts0202Evaluator{}, AuthFactor0104Evaluator{}}
	for _, e := range evals {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T : collecte échouée got %d, attendu NotAssessed", e, ha.ProposedImplLevel)
		}
	}
}

// Preuve illisible (JSON invalide) : NotAssessed, via errorAssessment.
func TestIdentitesAV_UnreadableEvidence(t *testing.T) {
	bad := assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: []byte("pas du json")}
	for _, e := range []assess.Evaluator{Dormant0103Evaluator{}, UniqueAccounts0202Evaluator{}, AuthFactor0104Evaluator{}} {
		if ha := e.Evaluate(bad); ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T : preuve illisible got %d, attendu NotAssessed", e, ha.ProposedImplLevel)
		}
	}
}
