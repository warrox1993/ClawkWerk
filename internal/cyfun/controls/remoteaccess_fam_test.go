package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// evalCase = une branche de décision commune aux trois contrôles de la famille.
type famCase struct {
	name       string
	ev         RemoteMFAEvidence
	wantLvl    cyfun.MaturityLevel
	wantStatus assess.Status
}

// famBranches : les 3 branches communes (les trois contrôles partagent la sonde
// RemoteMFAEvidence et la même règle de décision plafonnée à Defined).
var famBranches = []famCase{
	{"aucun accès distant", RemoteMFAEvidence{RemoteAccessEnabled: false}, cyfun.Defined, assess.StatusPass},
	{"distant durci", RemoteMFAEvidence{RemoteAccessEnabled: true, Hardened: true}, cyfun.Defined, assess.StatusPartial},
	{"distant exposé non durci", RemoteMFAEvidence{RemoteAccessEnabled: true, Hardened: false}, cyfun.Repeatable, assess.StatusFail},
}

// runFamTable exécute la table des 3 branches contre un évaluateur donné et
// vérifie le niveau, le statut ET le plafond Defined.
func runFamTable(t *testing.T, eval assess.Evaluator) {
	t.Helper()
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	for _, c := range famBranches {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := eval.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if len(ha.Findings) != 1 || ha.Findings[0].Status != c.wantStatus {
				t.Errorf("status: got %v want %v", ha.Findings, c.wantStatus)
			}
			// Honnêteté : contrôle MIXTE — le plafond est Defined(3), jamais au-dessus.
			if ha.ProposedImplLevel > cyfun.Defined {
				t.Errorf("plafond dépassé: %d > Defined", ha.ProposedImplLevel)
			}
		})
	}
}

func TestRemoteMFA0303Evaluator(t *testing.T)    { runFamTable(t, RemoteMFA0303Evaluator{}) }
func TestRemoteCrypto0304Evaluator(t *testing.T) { runFamTable(t, RemoteCrypto0304Evaluator{}) }
func TestRemoteMaint0812Evaluator(t *testing.T)  { runFamTable(t, RemoteMaint0812Evaluator{}) }

// TestRemoteAccessFamCollectError : collecte échouée → NotAssessed (jamais un score).
func TestRemoteAccessFamCollectError(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	evals := []assess.Evaluator{
		RemoteMFA0303Evaluator{},
		RemoteCrypto0304Evaluator{},
		RemoteMaint0812Evaluator{},
	}
	for _, e := range evals {
		// Collecte échouée.
		ha := e.Evaluate(assess.RawEvidence{Host: host, CollectErr: "timeout WinRM"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T collecte échouée: got %d want NotAssessed", e, ha.ProposedImplLevel)
		}
		if len(ha.Findings) != 1 || ha.Findings[0].Status != assess.StatusError {
			t.Errorf("%T collecte échouée: statut attendu Error, got %v", e, ha.Findings)
		}
		// Preuve illisible → NotAssessed également.
		ha = e.Evaluate(assess.RawEvidence{Host: host, Data: []byte("pas du json")})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T preuve illisible: got %d want NotAssessed", e, ha.ProposedImplLevel)
		}
	}
}

// TestRemoteAccessFamMeta : métadonnées essentielles (niveau, Key Measure, ID).
func TestRemoteAccessFamMeta(t *testing.T) {
	if PRAA0303Meta.Level != cyfun.LevelImportant || !PRAA0303Meta.KeyMeasure {
		t.Errorf("PR.AA-03.3 doit être Important + Key Measure: %+v", PRAA0303Meta)
	}
	if PRAA0304Meta.Level != cyfun.LevelEssential || PRAA0304Meta.KeyMeasure {
		t.Errorf("PR.AA-03.4 doit être Essential + non-KM: %+v", PRAA0304Meta)
	}
	if IDAM0812Meta.Level != cyfun.LevelImportant || IDAM0812Meta.KeyMeasure {
		t.Errorf("ID.AM-08.12 doit être Important + non-KM: %+v", IDAM0812Meta)
	}
}
