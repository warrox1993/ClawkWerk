package controls

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

func TestWebFilterEvaluator(t *testing.T) {
	host := assess.HostRef{ID: "PC-01", OS: "windows"}
	cases := []struct {
		name    string
		ev      WebFilterEvidence
		wantLvl cyfun.MaturityLevel
	}{
		{"ni proxy ni dns", WebFilterEvidence{}, cyfun.Initial},
		{"proxy seul", WebFilterEvidence{ProxyConfigured: true}, cyfun.Repeatable},
		{"dns seul", WebFilterEvidence{DNSFilteringHint: true}, cyfun.Repeatable},
		{"les deux", WebFilterEvidence{ProxyConfigured: true, DNSFilteringHint: true}, cyfun.Defined},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.ev)
			ha := WebFilterEvaluator{}.Evaluate(assess.RawEvidence{Host: host, Data: data})
			if ha.ProposedImplLevel != c.wantLvl {
				t.Errorf("niveau: got %d want %d", ha.ProposedImplLevel, c.wantLvl)
			}
			// Preuve PARTIELLE : le statut est TOUJOURS partial et le message
			// rappelle TOUJOURS l'attestation e-mail serveur.
			f := ha.Findings[0]
			if f.Status != assess.StatusPartial {
				t.Errorf("statut: got %q want %q", f.Status, assess.StatusPartial)
			}
			if !strings.Contains(f.Message, emailServerAttestation) {
				t.Errorf("message %q ne rappelle pas l'attestation e-mail serveur", f.Message)
			}
		})
	}
}

func TestWebFilterEvaluator_capsAtDefined(t *testing.T) {
	// Preuve partielle : même les deux indices web réunis ne dépassent JAMAIS
	// Defined(3) — le volet messagerie s'atteste hors scan.
	data, _ := json.Marshal(WebFilterEvidence{ProxyConfigured: true, DNSFilteringHint: true})
	ha := WebFilterEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC-01"}, Data: data})
	if ha.ProposedImplLevel > cyfun.Defined {
		t.Fatalf("le scan a proposé %d > Defined(3) — interdit pour une preuve partielle", ha.ProposedImplLevel)
	}
}

func TestWebFilterNormalizers(t *testing.T) {
	// Windows JSON : proxy activé, pas d'indice DNS.
	out, err := WebFilterWindowsNormalizer([]byte(`{"proxy_configured":true,"dns_filtering_hint":false}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev WebFilterEvidence
	json.Unmarshal(out, &ev)
	if !ev.ProxyConfigured || ev.DNSFilteringHint {
		t.Fatalf("normalisation Windows inattendue: %+v", ev)
	}
	// Linux 2 lignes : proxy oui, DNS non.
	out, err = WebFilterLinuxNormalizer([]byte("yes\nno\n"))
	if err != nil {
		t.Fatal(err)
	}
	ev = WebFilterEvidence{}
	json.Unmarshal(out, &ev)
	if !ev.ProxyConfigured || ev.DNSFilteringHint {
		t.Fatalf("normalisation Linux inattendue: %+v", ev)
	}
}

func TestWebFilterNormalizer_rejectsInvalid(t *testing.T) {
	// Windows : JSON invalide et champ obligatoire absent.
	if _, err := WebFilterWindowsNormalizer([]byte("pas du json")); err == nil {
		t.Error("attendu une erreur sur entrée non-JSON")
	}
	if _, err := WebFilterWindowsNormalizer([]byte(`{"dns_filtering_hint":true}`)); err == nil {
		t.Error("attendu une erreur sur proxy_configured absent")
	}
	// Linux : entrée vide.
	if _, err := WebFilterLinuxNormalizer([]byte("")); err == nil {
		t.Error("attendu une erreur sur entrée vide")
	}
}
