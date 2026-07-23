package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestLocalAdminEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name    string
		ev      LocalAdminEvidence
		wantLvl cyfun.MaturityLevel
	}{
		{"trop d'admins", LocalAdminEvidence{AdminCount: 8}, cyfun.Initial},
		{"quelques admins", LocalAdminEvidence{AdminCount: 4}, cyfun.Repeatable},
		{"maîtrisé, intégré actif", LocalAdminEvidence{AdminCount: 2, BuiltinAdminDisabled: false}, cyfun.Defined},
		{"maîtrisé, intégré désactivé", LocalAdminEvidence{AdminCount: 2, BuiltinAdminDisabled: true}, cyfun.Managed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := LocalAdminEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

func TestLocalAdminNormalizers(t *testing.T) {
	// Windows JSON.
	out, err := LocalAdminWindowsNormalizer([]byte(`{"admin_count":3,"builtin_admin_disabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev LocalAdminEvidence
	json.Unmarshal(out, &ev)
	if ev.AdminCount != 3 || !ev.BuiltinAdminDisabled {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 2 lignes : 2 admins, root verrouillé.
	out, err = LocalAdminLinuxNormalizer([]byte("2\nyes\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.AdminCount != 2 || !ev.BuiltinAdminDisabled {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}
