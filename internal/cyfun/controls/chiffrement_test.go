package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func encryptionRaw(t *testing.T, atRest, inTransit, removable bool) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(EncryptionEvidence{
		AtRestEnabled:      atRest,
		InTransitEnforced:  inTransit,
		RemovableEncrypted: removable,
	})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Chaque contrôle lit son propre fait booléen. Les deux SCAN purs passent à
// Managed/Pass (vrai) ou Initial/Fail (faux) ; le KM MIXTE passe à Defined/Pass
// (vrai) ou Repeatable/Partial (faux).
func TestChiffrement_Evaluators(t *testing.T) {
	cases := []struct {
		name       string
		eval       assess.Evaluator
		raw        assess.RawEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"DS0106 chiffré => Managed/Pass", AtRestEncryptionEvaluator{}, encryptionRaw(t, true, false, false), cyfun.Managed, assess.StatusPass},
		{"DS0106 non chiffré => Initial/Fail", AtRestEncryptionEvaluator{}, encryptionRaw(t, false, true, true), cyfun.Initial, assess.StatusFail},
		{"DS0202 imposé => Managed/Pass", InTransitEncryptionEvaluator{}, encryptionRaw(t, false, true, false), cyfun.Managed, assess.StatusPass},
		{"DS0202 non imposé => Initial/Fail", InTransitEncryptionEvaluator{}, encryptionRaw(t, true, false, true), cyfun.Initial, assess.StatusFail},
		{"DS0201 KM chiffré => Defined/Pass", RemovableEncryptionEvaluator{}, encryptionRaw(t, false, false, true), cyfun.Defined, assess.StatusPass},
		{"DS0201 KM non chiffré => Repeatable/Partial", RemovableEncryptionEvaluator{}, encryptionRaw(t, true, true, false), cyfun.Repeatable, assess.StatusPartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(c.raw)
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStatus {
				t.Errorf("statut: got %q want %q", ha.Findings[0].Status, c.wantStatus)
			}
		})
	}
}

// Les SCAN purs plafonnent à Managed, jamais au-delà, même sur un état parfait.
func TestChiffrement_ScanCapsAtManaged(t *testing.T) {
	for _, e := range []assess.Evaluator{AtRestEncryptionEvaluator{}, InTransitEncryptionEvaluator{}} {
		ha := e.Evaluate(encryptionRaw(t, true, true, true))
		if ha.ProposedImplLevel > cyfun.Managed {
			t.Fatalf("%T a proposé %d > Managed — plafond violé", e, ha.ProposedImplLevel)
		}
	}
}

// Le KM MIXTE ne dépasse jamais Defined, même sur un état parfait.
func TestChiffrement_RemovableCapsAtDefined(t *testing.T) {
	ha := RemovableEncryptionEvaluator{}.Evaluate(encryptionRaw(t, true, true, true))
	if ha.ProposedImplLevel > cyfun.Defined {
		t.Fatalf("PR.DS-02.1 MIXTE a proposé %d > Defined — plafond violé", ha.ProposedImplLevel)
	}
}

// Métadonnées : niveaux et flags Key Measure conformes à la source CCB.
func TestChiffrement_Meta(t *testing.T) {
	if PRDS0106Meta.Level != cyfun.LevelEssential || PRDS0106Meta.KeyMeasure {
		t.Error("PR.DS-01.6 doit être Essential + non-KM")
	}
	if PRDS0202Meta.Level != cyfun.LevelEssential || PRDS0202Meta.KeyMeasure {
		t.Error("PR.DS-02.2 doit être Essential + non-KM")
	}
	if PRDS0201Meta.Level != cyfun.LevelEssential || !PRDS0201Meta.KeyMeasure {
		t.Error("PR.DS-02.1 doit être Essential + Key Measure")
	}
}

// Une collecte échouée reste non fatale : NotAssessed, pas une fausse faille.
func TestChiffrement_CollectErrIsNotAssessed(t *testing.T) {
	for _, e := range []assess.Evaluator{AtRestEncryptionEvaluator{}, InTransitEncryptionEvaluator{}, RemovableEncryptionEvaluator{}} {
		ha := e.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
		if ha.ProposedImplLevel != cyfun.NotAssessed {
			t.Errorf("%T collecte échouée: got %d, attendu NotAssessed", e, ha.ProposedImplLevel)
		}
	}
}

func TestEncryptionWindowsNormalizer(t *testing.T) {
	raw := []byte(`{"at_rest_enabled":true,"in_transit_enforced":false,"removable_encrypted":true}`)
	out, err := EncryptionWindowsNormalizer(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev EncryptionEvidence
	json.Unmarshal(out, &ev)
	if !ev.AtRestEnabled || ev.InTransitEnforced || !ev.RemovableEncrypted {
		t.Fatalf("mapping Windows inattendu: %+v", ev)
	}
}

func TestEncryptionWindowsNormalizer_MissingField(t *testing.T) {
	if _, err := EncryptionWindowsNormalizer([]byte(`{"in_transit_enforced":true}`)); err == nil {
		t.Fatal("champ at_rest_enabled absent doit produire une erreur")
	}
}

func TestEncryptionLinuxNormalizer(t *testing.T) {
	out, err := EncryptionLinuxNormalizer([]byte("yes\nno\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev EncryptionEvidence
	json.Unmarshal(out, &ev)
	if !ev.AtRestEnabled || ev.InTransitEnforced || ev.RemovableEncrypted {
		t.Fatalf("mapping Linux inattendu: %+v", ev)
	}
}

func TestEncryptionLinuxNormalizer_Empty(t *testing.T) {
	if _, err := EncryptionLinuxNormalizer([]byte("   \n")); err == nil {
		t.Fatal("sortie vide doit produire une erreur")
	}
}
