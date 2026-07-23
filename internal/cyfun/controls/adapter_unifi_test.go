package controls

import "testing"

// UniFi est désormais couvert via l'API du contrôleur (transport api) : son
// adaptateur pare-feu doit être enregistré en « d'après-doc-non-validé »
// (plus StatusStub). Le parsing JSON est testé dans netapi_test.go.
func TestUnifiRegistered_DocsUnverified(t *testing.T) {
	for _, a := range NetFirewallCoverage() {
		if a.Platform == PlatformUniFi {
			if a.Status != StatusDocsUnverified {
				t.Fatalf("UniFi attendu %q, obtenu %q", StatusDocsUnverified, a.Status)
			}
			return
		}
	}
	t.Fatal("adaptateur pare-feu UniFi non enregistré")
}
