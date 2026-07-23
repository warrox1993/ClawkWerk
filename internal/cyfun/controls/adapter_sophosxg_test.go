package controls

import "testing"

// Sophos est désormais couvert via l'API XML (transport api) : son adaptateur
// pare-feu doit être enregistré en « d'après-doc-non-validé » (plus StatusStub).
// Le parsing XML est testé dans netapi_test.go.
func TestSophosRegistered_DocsUnverified(t *testing.T) {
	for _, a := range NetFirewallCoverage() {
		if a.Platform == PlatformSophosXG {
			if a.Status != StatusDocsUnverified {
				t.Fatalf("Sophos attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
			return
		}
	}
	t.Fatal("adaptateur pare-feu Sophos non enregistré")
}
