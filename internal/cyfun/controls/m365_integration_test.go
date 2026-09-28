package controls

import (
	"encoding/json"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// La preuve M365 (IdP autoritaire) prouve RÉELLEMENT la MFA : elle dépasse le
// plafond « host-side » (Defined) et atteint Managed — ce que le côté hôte ne
// peut pas. Une MFA non imposée côté M365 échoue franchement.
func TestM365MFANormalizer_Evaluator(t *testing.T) {
	enforced, _ := M365MFANormalizer([]byte(`{"security_defaults":{"isEnabled":true},"conditional_access":{"value":[]}}`))
	ha := RemoteMFAEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "tenant"}, Data: enforced})
	if ha.ProposedImplLevel != cyfun.Managed {
		t.Errorf("MFA imposée M365 → Managed attendu, obtenu %d", ha.ProposedImplLevel)
	}

	notEnforced, _ := M365MFANormalizer([]byte(`{"security_defaults":{"isEnabled":false},"conditional_access":{"value":[]}}`))
	ha2 := RemoteMFAEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "tenant"}, Data: notEnforced})
	if ha2.ProposedImplLevel != cyfun.Initial {
		t.Errorf("MFA non imposée M365 → Initial attendu, obtenu %d", ha2.ProposedImplLevel)
	}

	// Chemin host-side inchangé (MfaEnforced nil) : plafond Defined préservé.
	ha3 := RemoteMFAEvaluator{}.Evaluate(assess.RawEvidence{Host: assess.HostRef{ID: "PC1"}, Data: []byte(`{"remote_access_enabled":true,"hardened":true}`)})
	if ha3.ProposedImplLevel > cyfun.Defined {
		t.Errorf("côté hôte : plafond Defined attendu, obtenu %d", ha3.ProposedImplLevel)
	}
}

func TestM365InventoryNormalizer(t *testing.T) {
	out, err := M365InventoryNormalizer([]byte(`{"subscribed_skus":{"value":[{"capabilityStatus":"Enabled"},{"capabilityStatus":"Enabled"}]},"domains":{"value":[{"isVerified":true}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev SoftwareInventoryEvidence
	json.Unmarshal(out, &ev)
	if ev.InstalledCount != 3 { // 2 SKU Enabled + 1 domaine vérifié
		t.Errorf("3 services cloud attendus, obtenu %d", ev.InstalledCount)
	}
}

func TestM365Normalizers_RejectGarbage(t *testing.T) {
	if _, err := M365MFANormalizer([]byte("pas du json")); err == nil {
		t.Error("M365MFANormalizer devrait rejeter un JSON invalide")
	}
	if _, err := M365InventoryNormalizer([]byte("pas du json")); err == nil {
		t.Error("M365InventoryNormalizer devrait rejeter un JSON invalide")
	}
}
