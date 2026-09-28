package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func TestIdentityEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name    string
		ev      IdentityEvidence
		wantLvl cyfun.MaturityLevel
	}{
		{"pas de politique", IdentityEvidence{MinPasswordLength: 0}, cyfun.Initial},
		{"trop court", IdentityEvidence{MinPasswordLength: 6, LockoutThreshold: 5, GuestAccountDisabled: true}, cyfun.Initial},
		{"basique sans verrouillage", IdentityEvidence{MinPasswordLength: 8, GuestAccountDisabled: true}, cyfun.Repeatable},
		{"correcte", IdentityEvidence{MinPasswordLength: 8, LockoutThreshold: 5, GuestAccountDisabled: true}, cyfun.Defined},
		{"robuste", IdentityEvidence{MinPasswordLength: 14, LockoutThreshold: 5, GuestAccountDisabled: true}, cyfun.Managed},
		{"robuste mais invité actif", IdentityEvidence{MinPasswordLength: 14, LockoutThreshold: 5, GuestAccountDisabled: false}, cyfun.Repeatable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := IdentityEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

func TestIdentityEvaluator_capsAtManaged(t *testing.T) {
	// Le scan ne doit JAMAIS proposer Optimizing (5) : le 5 s'atteste par preuve
	// organisationnelle via override tracé, jamais déduit d'un scan hôte.
	data, _ := json.Marshal(IdentityEvidence{MinPasswordLength: 30, MaxPasswordAgeDays: 90, LockoutThreshold: 3, GuestAccountDisabled: true})
	ha := IdentityEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
	if ha.ProposedImplLevel > cyfun.Managed {
		t.Fatalf("le scan a proposé %d > Managed(4) — interdit", ha.ProposedImplLevel)
	}
}

// La sortie `net accounts` est parsée de façon MULTILINGUE : on vérifie EN, FR, NL
// et DE (les 4 langues officielles belges + anglais). Le verrouillage « Never/
// Jamais/Nooit/Nie » (non numérique) doit valoir 0.
func TestIdentityWindowsNormalizer_MultiLingual(t *testing.T) {
	cases := map[string]string{
		"EN": "Minimum password length:                     8\n" +
			"Maximum password age (days):                 42\n" +
			"Lockout threshold:                           Never\n" +
			"GUEST_DISABLED=1\n",
		"FR": "Longueur minimale du mot de passe :          8\n" +
			"Durée de vie maximale du mot de passe (jours) : 42\n" +
			"Seuil de verrouillage :                      Jamais\n" +
			"GUEST_DISABLED=1\n",
		"NL": "Minimale wachtwoordlengte:                   8\n" +
			"Maximale wachtwoordduur (dagen):             42\n" +
			"Vergrendelingsdrempel:                       Nooit\n" +
			"GUEST_DISABLED=1\n",
		"DE": "Minimale Kennwortlänge:                      8\n" +
			"Maximales Kennwortalter (Tage):              42\n" +
			"Sperrschwelle:                               Nie\n" +
			"GUEST_DISABLED=1\n",
	}
	for lang, raw := range cases {
		t.Run(lang, func(t *testing.T) {
			out, err := IdentityWindowsNormalizer([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			var ev IdentityEvidence
			json.Unmarshal(out, &ev)
			if ev.MinPasswordLength != 8 || ev.MaxPasswordAgeDays != 42 {
				t.Errorf("[%s] longueur/âge inattendus: %+v", lang, ev)
			}
			if ev.LockoutThreshold != 0 { // « Never » traduit -> 0
				t.Errorf("[%s] verrouillage non numérique doit valoir 0, obtenu %d", lang, ev.LockoutThreshold)
			}
			if !ev.GuestAccountDisabled {
				t.Errorf("[%s] compte invité désactivé (GUEST_DISABLED=1) attendu", lang)
			}
		})
	}
}

func TestIdentityWindowsNormalizer_NumericLockoutAndActiveGuest(t *testing.T) {
	raw := "Minimum password length:  10\nLockout threshold:  5\nGUEST_DISABLED=0\n"
	out, err := IdentityWindowsNormalizer([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var ev IdentityEvidence
	json.Unmarshal(out, &ev)
	if ev.MinPasswordLength != 10 || ev.LockoutThreshold != 5 || ev.GuestAccountDisabled {
		t.Fatalf("attendu min 10, lockout 5, invité actif ; obtenu %+v", ev)
	}
}

func TestIdentityLinuxNormalizer(t *testing.T) {
	out, err := IdentityLinuxNormalizer([]byte("10\n365\nyes\nyes\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev IdentityEvidence
	json.Unmarshal(out, &ev)
	if ev.MinPasswordLength != 10 || ev.MaxPasswordAgeDays != 365 || ev.LockoutThreshold == 0 || !ev.GuestAccountDisabled {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestIdentityNormalizer_rejectsGarbage(t *testing.T) {
	// Sortie sans libellé reconnu (aucune langue) -> erreur, pas un faux 0.
	if _, err := IdentityWindowsNormalizer([]byte("blah blah\nGUEST_DISABLED=1")); err == nil {
		t.Error("attendu une erreur si la longueur minimale est introuvable")
	}
	if _, err := IdentityLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
}
