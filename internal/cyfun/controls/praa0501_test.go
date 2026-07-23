package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestAccessReviewEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name       string
		ev         AccessReviewEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"énumération impossible", AccessReviewEvidence{TotalLocalAccounts: 0}, cyfun.Initial, assess.StatusFail},
		{"beaucoup de dormants", AccessReviewEvidence{InactiveAccounts: 7, TotalLocalAccounts: 20}, cyfun.Repeatable, assess.StatusPartial},
		{"quelques dormants", AccessReviewEvidence{InactiveAccounts: 2, TotalLocalAccounts: 20}, cyfun.Defined, assess.StatusPartial},
		{"aucun dormant", AccessReviewEvidence{InactiveAccounts: 0, TotalLocalAccounts: 20}, cyfun.Defined, assess.StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := AccessReviewEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut: got %q want %q", ha.Findings[0].Status, c.wantStatus)
			}
		})
	}
}

// Plafond de preuve partielle : jamais au-dessus de Defined (3), même sans
// aucun compte dormant. La revue périodique formelle reste organisationnelle.
func TestAccessReviewCapsAtDefined(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "linux"}
	data, _ := json.Marshal(AccessReviewEvidence{InactiveAccounts: 0, TotalLocalAccounts: 50})
	ha := AccessReviewEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
	if ha.ProposedImplLevel > cyfun.Defined {
		t.Fatalf("plafond dépassé : got %d, attendu <= Defined (%d)", ha.ProposedImplLevel, cyfun.Defined)
	}
}

func TestAccessReviewNormalizers(t *testing.T) {
	// Windows JSON.
	out, err := AccessReviewWindowsNormalizer([]byte(`{"inactive_accounts":3,"total_local_accounts":12}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev AccessReviewEvidence
	json.Unmarshal(out, &ev)
	if ev.InactiveAccounts != 3 || ev.TotalLocalAccounts != 12 {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 2 lignes : total, puis dormants.
	out, err = AccessReviewLinuxNormalizer([]byte("12\n3\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.TotalLocalAccounts != 12 || ev.InactiveAccounts != 3 {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestAccessReviewNormalizersReject(t *testing.T) {
	// Windows : champ total_local_accounts absent.
	if _, err := AccessReviewWindowsNormalizer([]byte(`{"inactive_accounts":3}`)); err == nil {
		t.Error("Windows : total_local_accounts absent aurait dû échouer")
	}
	// Windows : JSON illisible.
	if _, err := AccessReviewWindowsNormalizer([]byte(`pas du json`)); err == nil {
		t.Error("Windows : JSON illisible aurait dû échouer")
	}
	// Linux : sortie vide.
	if _, err := AccessReviewLinuxNormalizer([]byte("   \n")); err == nil {
		t.Error("Linux : sortie vide aurait dû échouer")
	}
	// Linux : première ligne non entière.
	if _, err := AccessReviewLinuxNormalizer([]byte("abc\n3\n")); err == nil {
		t.Error("Linux : total non entier aurait dû échouer")
	}
}
