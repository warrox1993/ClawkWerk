package controls

import (
	"encoding/json"
	"testing"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
)

func TestHardeningEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "linux"}
	cases := []struct {
		name    string
		ev      HardeningEvidence
		wantLvl cyfun.MaturityLevel
	}{
		{"legacy présent", HardeningEvidence{LegacyServices: 1, OpenListeningPorts: 3}, cyfun.Initial},
		{"surface large", HardeningEvidence{LegacyServices: 0, OpenListeningPorts: 20}, cyfun.Repeatable},
		{"surface modérée", HardeningEvidence{LegacyServices: 0, OpenListeningPorts: 10}, cyfun.Defined},
		{"surface minimale", HardeningEvidence{LegacyServices: 0, OpenListeningPorts: 3}, cyfun.Managed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := HardeningEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
		})
	}
}

func TestHardeningEvaluator_capsAtManaged(t *testing.T) {
	// Le scan ne doit JAMAIS proposer Optimizing (5) : le 5 s'atteste par preuve
	// organisationnelle via override tracé, jamais déduit d'un scan hôte.
	data, _ := json.Marshal(HardeningEvidence{LegacyServices: 0, OpenListeningPorts: 0})
	ha := HardeningEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
	if ha.ProposedImplLevel > cyfun.Managed {
		t.Fatalf("le scan a proposé %d > Managed(4) — interdit", ha.ProposedImplLevel)
	}
}

func TestHardeningNormalizers(t *testing.T) {
	// Windows JSON.
	out, err := HardeningWindowsNormalizer([]byte(`{"legacy_services":2,"open_listening_ports":18}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev HardeningEvidence
	json.Unmarshal(out, &ev)
	if ev.LegacyServices != 2 || ev.OpenListeningPorts != 18 {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 2 lignes : total ports, puis nb legacy.
	out, err = HardeningLinuxNormalizer([]byte("12\n1\n"))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out, &ev)
	if ev.OpenListeningPorts != 12 || ev.LegacyServices != 1 {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestHardeningNormalizer_rejectsGarbage(t *testing.T) {
	if _, err := HardeningWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := HardeningWindowsNormalizer([]byte(`{"legacy_services":2}`)); err == nil {
		t.Error("attendu une erreur quand open_listening_ports est absent")
	}
	if _, err := HardeningLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
	if _, err := HardeningLinuxNormalizer([]byte("abc\n")); err == nil {
		t.Error("attendu une erreur sur nombre de ports illisible")
	}
}
