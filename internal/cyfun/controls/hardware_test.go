package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func hardwareRaw(t *testing.T, items int) assess.RawEvidence {
	t.Helper()
	data, _ := json.Marshal(HardwareEvidence{ItemsEnumerated: items})
	return assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, Data: data}
}

// Les 3 contrôles réutilisent la MÊME sonde Hardware et la MÊME règle MIXTE :
// énumération impossible => Initial/Fail ; énumération réussie => Defined/Partial
// (plafond MIXTE : le recoupement documenté + détection du non-autorisé restent
// organisationnels).
func TestHardware_Evaluators(t *testing.T) {
	cases := []struct {
		name     string
		eval     assess.Evaluator
		items    int
		wantLvl  cyfun.MaturityLevel
		wantStat assess.Status
	}{
		{"AM0102 énumération impossible", HwInv0102Evaluator{}, 0, cyfun.Initial, assess.StatusFail},
		{"AM0102 compte négatif (illisible)", HwInv0102Evaluator{}, -1, cyfun.Initial, assess.StatusFail},
		{"AM0102 énumérable => Defined/Partial", HwInv0102Evaluator{}, 128, cyfun.Defined, assess.StatusPartial},
		{"AM0103 énumération impossible", HwInv0103Evaluator{}, 0, cyfun.Initial, assess.StatusFail},
		{"AM0103 énumérable => Defined/Partial", HwInv0103Evaluator{}, 42, cyfun.Defined, assess.StatusPartial},
		{"AM0104 énumération impossible", HwDet0104Evaluator{}, 0, cyfun.Initial, assess.StatusFail},
		{"AM0104 énumérable => Defined/Partial", HwDet0104Evaluator{}, 7, cyfun.Defined, assess.StatusPartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ha := c.eval.Evaluate(hardwareRaw(t, c.items))
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if ha.Findings[0].Status != c.wantStat {
				t.Errorf("status: got %s want %s", ha.Findings[0].Status, c.wantStat)
			}
		})
	}
}

// Le scan MIXTE ne doit JAMAIS dépasser Defined, même sur un parc matériel
// gigantesque. Le « documenté/tenu à jour + détection du non-autorisé »
// (Managed/Optimizing) relève de l'axe Documentation, jamais d'un scan hôte.
func TestHardware_CapsAtDefined(t *testing.T) {
	for _, eval := range []assess.Evaluator{HwInv0102Evaluator{}, HwInv0103Evaluator{}, HwDet0104Evaluator{}} {
		ha := eval.Evaluate(hardwareRaw(t, 1000000))
		if ha.ProposedImplLevel > cyfun.Defined {
			t.Fatalf("le scan a proposé %d > Defined(3) — plafond MIXTE violé", ha.ProposedImplLevel)
		}
	}
}

// Une collecte échouée reste non fatale : NotAssessed, pas une fausse faille.
func TestHardware_CollectErrIsNotAssessed(t *testing.T) {
	ha := HwInv0102Evaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "H1"}, CollectErr: "hôte injoignable"})
	if ha.ProposedImplLevel != cyfun.NotAssessed || ha.Findings[0].Status != assess.StatusError {
		t.Fatalf("collecte échouée mal gérée: %+v", ha)
	}
}

// Preuve illisible => NotAssessed / StatusError, jamais un score inventé.
func TestHardware_UnreadableEvidence(t *testing.T) {
	ha := HwDet0104Evaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "X"}, Data: []byte("{pas du json")})
	if ha.ProposedImplLevel != cyfun.NotAssessed || ha.Findings[0].Status != assess.StatusError {
		t.Fatalf("preuve illisible mal gérée: %+v", ha)
	}
}

// Les métadonnées portent le bon niveau et le bon flag KM.
func TestHardware_Meta(t *testing.T) {
	if IDAM0102Meta.Level != cyfun.LevelImportant || IDAM0102Meta.KeyMeasure {
		t.Error("ID.AM-01.2 doit être Important + non-KM")
	}
	if IDAM0103Meta.Level != cyfun.LevelImportant || IDAM0103Meta.KeyMeasure {
		t.Error("ID.AM-01.3 doit être Important + non-KM")
	}
	if IDAM0104Meta.Level != cyfun.LevelEssential || IDAM0104Meta.KeyMeasure {
		t.Error("ID.AM-01.4 doit être Essential + non-KM")
	}
}

func TestHardwareNormalizers(t *testing.T) {
	// Windows JSON {items_enumerated}.
	out, err := HardwareWindowsNormalizer([]byte(`{"items_enumerated":213}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev HardwareEvidence
	json.Unmarshal(out, &ev)
	if ev.ItemsEnumerated != 213 {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux : 1 ligne entière = le nombre.
	out, err = HardwareLinuxNormalizer([]byte("57\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.ItemsEnumerated != 57 {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestHardwareNormalizer_rejectsGarbage(t *testing.T) {
	if _, err := HardwareWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := HardwareWindowsNormalizer([]byte(`{}`)); err == nil {
		t.Error("attendu une erreur quand items_enumerated est absent")
	}
	if _, err := HardwareLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
	if _, err := HardwareLinuxNormalizer([]byte("abc\n")); err == nil {
		t.Error("attendu une erreur sur nombre illisible")
	}
}
