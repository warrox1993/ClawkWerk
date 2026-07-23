package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestRemoteMFAEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name       string
		ev         RemoteMFAEvidence
		wantLvl    cyfun.MaturityLevel
		wantStatus assess.Status
	}{
		{"aucun accès distant", RemoteMFAEvidence{RemoteAccessEnabled: false}, cyfun.Defined, assess.StatusPass},
		{"distant durci", RemoteMFAEvidence{RemoteAccessEnabled: true, Hardened: true}, cyfun.Defined, assess.StatusPartial},
		{"distant exposé non durci", RemoteMFAEvidence{RemoteAccessEnabled: true, Hardened: false}, cyfun.Repeatable, assess.StatusFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := RemoteMFAEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			if len(ha.Findings) != 1 || ha.Findings[0].Status != c.wantStatus {
				t.Errorf("status: got %v want %v", ha.Findings, c.wantStatus)
			}
			// Honnêteté : le plafond est Defined(3) — jamais au-dessus.
			if ha.ProposedImplLevel > cyfun.Defined {
				t.Errorf("plafond dépassé: %d > Defined", ha.ProposedImplLevel)
			}
		})
	}
}

func TestRemoteMFANormalizers(t *testing.T) {
	// Windows JSON : RDP activé + NLA requis.
	out, err := RemoteMFAWindowsNormalizer([]byte(`{"remote_access_enabled":true,"hardened":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev RemoteMFAEvidence
	json.Unmarshal(out, &ev)
	if !ev.RemoteAccessEnabled || !ev.Hardened {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 2 lignes : SSH actif, clé-uniquement.
	out, err = RemoteMFALinuxNormalizer([]byte("yes\nyes\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if !ev.RemoteAccessEnabled || !ev.Hardened {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
	// Linux : SSH actif mais mot de passe autorisé → non durci.
	out, _ = RemoteMFALinuxNormalizer([]byte("yes\nno\n"))
	json.Unmarshal(out, &ev)
	if !ev.RemoteAccessEnabled || ev.Hardened {
		t.Fatalf("normalisation Linux (non durci) inattendue: %+v", ev)
	}
}

func TestRemoteMFANormalizersEmpty(t *testing.T) {
	// Windows : champ obligatoire absent.
	if _, err := RemoteMFAWindowsNormalizer([]byte(`{"hardened":true}`)); err == nil {
		t.Error("Windows : champ remote_access_enabled absent devrait échouer")
	}
	// Windows : JSON illisible.
	if _, err := RemoteMFAWindowsNormalizer([]byte(`pas du json`)); err == nil {
		t.Error("Windows : JSON illisible devrait échouer")
	}
	// Linux : entrée vide.
	if _, err := RemoteMFALinuxNormalizer([]byte("   \n\n")); err == nil {
		t.Error("Linux : entrée vide devrait échouer")
	}
}
